#!/usr/bin/env python3
"""wh: общая память WorkHack в бакете Cloudflare R2 (S3-совместимо).

Только стандартная библиотека Python 3.9+. Команды: setup, doctor, start, log/done/handoff/fail/note,
claim, flush, ls, get, put, push-context, pack, ingest, hook. Справка: wh --help.

Раскладка бакета:
  context/*.md                     общий контекст (core.md грузится всегда)
  state.md                         текущее состояние (собирается из событий)
  events/ГГГГ-ММ-ДД/ЧЧММСС-кто-вид-xxxxxx.json   неизменяемые события (только добавление)
  claims/<задача>.json             кто взял задачу (атомарно, If-None-Match)
  done/<задача>.json               задача закрыта
  assets/ queue/ ready/ snapshots/ рабочие файлы
"""
import argparse
import datetime
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

HOME = Path(os.environ.get("WH_HOME") or Path.home() / ".workhack")
EVENT_KINDS = ("claim", "done", "handoff", "fail", "note", "start", "session-end", "report", "checkpoint")
CLOSING = ("done", "handoff", "fail", "note")   # любое из них = «итог записан»
LOG_MODES = ("full", "prompts", "off")  # full: сообщения пользователя и ответы ИИ; prompts: только пользователь
MSG_LIMIT = 4000                        # символов на одно сообщение в журнале
CONFIG_KEYS = {"log_messages": LOG_MODES, "who": None}   # что можно менять командой wh config (None = любое имя)
CLAIM_TTL_MIN = 90
UTC = datetime.timezone.utc


class ConfigError(Exception):
    pass


class NetError(Exception):
    pass


class S3Error(Exception):
    def __init__(self, status, text=""):
        super().__init__("HTTP %s %s" % (status, text))
        self.status = status


# ───────────────────────── S3 / SigV4 ─────────────────────────

def _q(s):
    return urllib.parse.quote(s, safe="~")


def sign(method, url, headers, payload_hash, access, secret, region="auto", service="s3", now=None):
    now = now or datetime.datetime.now(UTC)
    u = urllib.parse.urlsplit(url)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    day = amz[:8]
    h = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    h.update({"host": u.netloc, "x-amz-date": amz, "x-amz-content-sha256": payload_hash})
    names = sorted(h)
    signed = ";".join(names)
    query = sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    canonical = "\n".join([
        method, u.path or "/", "&".join("%s=%s" % (_q(k), _q(v)) for k, v in query),
        "".join("%s:%s\n" % (n, h[n]) for n in names), signed, payload_hash])
    scope = "%s/%s/%s/aws4_request" % (day, region, service)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret).encode()
    for part in (day, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = dict(headers)
    out.update({"x-amz-date": amz, "x-amz-content-sha256": payload_hash,
                "Authorization": "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                                 % (access, scope, signed, sig)})
    return out


CA_CANDIDATES = ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                 "/etc/pki/tls/certs/ca-bundle.crt", "/opt/homebrew/etc/openssl@3/cert.pem")


def ssl_context():
    """Python с python.org на macOS приходит без корневых сертификатов: берём системный файл."""
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats()["x509_ca"] == 0:
        paths = [os.environ.get("SSL_CERT_FILE", "")] + list(CA_CANDIDATES)
        for path in paths:
            if path and os.path.exists(path):
                ctx.load_verify_locations(cafile=path)
                break
    return ctx


class S3:
    def __init__(self, endpoint, bucket, access, secret, region="auto", timeout=15):
        self.endpoint, self.bucket = endpoint.rstrip("/"), bucket
        self.access, self.secret, self.region, self.timeout = access, secret, region, timeout

    def _req(self, method, key="", query=None, body=b"", headers=None):
        path = "/" + self.bucket + ("/" + urllib.parse.quote(key, safe="/~") if key else "")
        qs = "&".join("%s=%s" % (_q(k), _q(v)) for k, v in sorted((query or {}).items()))
        url = self.endpoint + path + ("?" + qs if qs else "")
        signed = sign(method, url, headers or {}, hashlib.sha256(body).hexdigest(),
                      self.access, self.secret, self.region)
        req = urllib.request.Request(url, data=body if method == "PUT" else None, method=method, headers=signed)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context()) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except (urllib.error.URLError, OSError) as e:
            raise NetError(str(e))

    @staticmethod
    def _fail(status, body):
        hint = " (проверь ключи и права токена на этот бакет)" if status in (401, 403) else ""
        raise S3Error(status, body[:200].decode("utf-8", "replace") + hint)

    def put(self, key, data, if_none_match=False, if_match=None):
        h = {}
        if if_none_match:
            h["If-None-Match"] = "*"
        if if_match:
            h["If-Match"] = if_match
        status, _, body = self._req("PUT", key, body=data, headers=h)
        if status in (409, 412):
            return False
        if status >= 300:
            self._fail(status, body)
        return True

    def get(self, key):
        status, hdr, body = self._req("GET", key)
        if status == 404:
            return None
        if status >= 300:
            self._fail(status, body)
        return body, {k.lower(): v for k, v in hdr.items()}.get("etag")

    def head(self, key):
        status, hdr, body = self._req("HEAD", key)
        if status == 404:
            return None
        if status >= 300:
            self._fail(status, body)
        return {k.lower(): v for k, v in hdr.items()}.get("etag") or ""

    def delete(self, key):
        status, _, body = self._req("DELETE", key)
        if status >= 300 and status != 404:
            self._fail(status, body)

    def list(self, prefix=""):
        keys, token = [], None
        while True:
            q = {"list-type": "2", "prefix": prefix}
            if token:
                q["continuation-token"] = token
            status, _, body = self._req("GET", "", query=q)
            if status >= 300:
                self._fail(status, body)
            root = ET.fromstring(body)
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            keys += [e.findtext(ns + "Key") for e in root.iter(ns + "Contents")]
            if (root.findtext(ns + "IsTruncated") or "").lower() != "true":
                return keys
            token = root.findtext(ns + "NextContinuationToken")


# ───────────────────────── настройки ─────────────────────────

ENV_MAP = {"WH_ACCOUNT_ID": "account_id", "WH_BUCKET": "bucket", "WH_JURISDICTION": "jurisdiction",
           "WH_WHO": "who", "WH_ENDPOINT": "endpoint", "WH_ACCESS_KEY_ID": "access_key_id",
           "WH_SECRET_ACCESS_KEY": "secret_access_key", "WH_LOG_MESSAGES": "log_messages"}


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def settings():
    cfg = {}
    cfg.update(_read_json(HOME / "config.json"))
    cfg.update(_read_json(HOME / "credentials"))
    cfg.update({v: os.environ[k] for k, v in ENV_MAP.items() if os.environ.get(k)})
    cfg.setdefault("who", getpass.getuser())
    return cfg


def missing(cfg):
    need = [k for k in ("bucket", "access_key_id", "secret_access_key") if not cfg.get(k)]
    if not (cfg.get("endpoint") or cfg.get("account_id")):
        need.append("account_id")
    return need


def endpoint_of(cfg):
    if cfg.get("endpoint"):
        return cfg["endpoint"]
    zone = {"eu": "eu.", "fedramp": "fedramp."}.get(cfg.get("jurisdiction") or "", "")
    return "https://%s.%sr2.cloudflarestorage.com" % (cfg["account_id"], zone)


def client(cfg):
    gaps = missing(cfg)
    if gaps:
        raise ConfigError("не хватает настроек: %s. Запусти: wh setup" % ", ".join(gaps))
    return S3(endpoint_of(cfg), cfg["bucket"], cfg["access_key_id"], cfg["secret_access_key"])


# ───────────────────────── события ─────────────────────────

SECRET_KV = re.compile(r"(?i)\b(token|secret|password|passwd|api[_-]?key|key)\b\s*[:=]\s*\S+")
LONG_TOKEN = re.compile(r"(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]{32,}")


def scrub(text):
    text = SECRET_KV.sub(lambda m: m.group(1) + "=[скрыто]", text)
    return LONG_TOKEN.sub("[скрыто]", text)


def make_event(kind, who, task, msg, files, now):
    return {"v": 1, "ts": now.isoformat(timespec="seconds"), "who": who, "kind": kind, "task": task or "",
            "msg": scrub(msg or ""), "files": list(files or []), "host": socket.gethostname()}


def event_key(ev, now):
    return "events/%s/%s-%s-%s-%s.json" % (now.strftime("%Y-%m-%d"), now.strftime("%H%M%S"),
                                            re.sub(r"[^\w+.-]", "_", ev["who"]), ev["kind"], secrets.token_hex(3))


def _atomic_write(path, text, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode or 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(str(tmp), str(path))


def queue_event(key, body):
    _atomic_write(HOME / "outbox" / (key.replace("/", "__")), json.dumps({"key": key, "body": body}), 0o600)


def flush_outbox(s3):
    sent = 0
    for p in sorted((HOME / "outbox").glob("*")) if (HOME / "outbox").exists() else []:
        item = _read_json(p)
        if not item:
            continue
        s3.put(item["key"], item["body"].encode("utf-8"), if_none_match=True)  # повтор безопасен
        p.unlink()
        sent += 1
    return sent


def record(kind, msg="", task="", files=(), suffix=""):
    """Пишет событие. Возвращает ('ok'|'queued', key)."""
    now = datetime.datetime.now(UTC)
    cfg = settings()
    ev = make_event(kind, cfg["who"] + ("+" + suffix if suffix else ""), task, msg, files, now)
    key, body = event_key(ev, now), json.dumps(ev, ensure_ascii=False)
    if kind in CLOSING:
        _atomic_write(HOME / "last_close", repr(time.time()))
    marker = (lambda s3: s3.put("done/%s.json" % task, body.encode("utf-8"), if_none_match=True)) \
        if kind == "done" and task else None
    return _deliver(cfg, key, body, marker)


def _deliver(cfg, key, body, after=None):
    """Кладёт объект в бакет. Нет связи или настроек: в локальную очередь. -> ('ok'|'queued', подробности)"""
    try:
        s3 = client(cfg)
        s3.put(key, body.encode("utf-8"), if_none_match=True)
        if after:
            after(s3)
        flush_outbox(s3)
        return "ok", key
    except (ConfigError, NetError) as e:
        queue_event(key, body)
        return "queued", "%s (%s)" % (key, e)


def record_message(role, text, session):
    """Журнал сообщений: messages/ГГГГ-ММ-ДД/…json. Режим: full (всё), prompts (только пользователь), off."""
    cfg = settings()
    mode = cfg.get("log_messages") if cfg.get("log_messages") in LOG_MODES else "full"
    if mode == "off" or (mode == "prompts" and role != "user") or not (text or "").strip():
        return
    now = datetime.datetime.now(UTC)
    msg = {"v": 1, "ts": now.isoformat(timespec="seconds"), "who": cfg["who"], "role": role,
           "session": session or "", "text": scrub(text.strip())[:MSG_LIMIT]}
    key = "messages/%s/%s-%s-%s-%s.json" % (now.strftime("%Y-%m-%d"), now.strftime("%H%M%S"),
                                             re.sub(r"[^\w+.-]", "_", cfg["who"]), role, secrets.token_hex(3))
    _deliver(cfg, key, json.dumps(msg, ensure_ascii=False))


def last_assistant_text(path):
    """Последний ответ ИИ (только текст) из транскрипта Claude Code (jsonl). Читает хвост файла."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 2_000_000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except (OSError, TypeError):
        return ""
    for line in reversed(lines):
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("type") == "assistant":
            parts = [c.get("text", "") for c in obj.get("message", {}).get("content", []) if isinstance(c, dict) and c.get("type") == "text"]
            if any(p.strip() for p in parts):
                return "\n".join(parts)
    return ""


def _age_min(ts):
    return (datetime.datetime.now(UTC) - datetime.datetime.fromisoformat(ts)).total_seconds() / 60


def claim(s3, task, who, ttl=CLAIM_TTL_MIN):
    """-> ('won'|'taken'|'done', holder)"""
    if s3.head("done/%s.json" % task) is not None:
        return "done", ""
    key = "claims/%s.json" % task
    body = json.dumps({"task": task, "who": who, "ts": datetime.datetime.now(UTC).isoformat(timespec="seconds")})
    if s3.put(key, body.encode(), if_none_match=True):
        return "won", who
    cur = s3.get(key)
    if cur is None:
        return claim(s3, task, who, ttl)
    info = _read_json_bytes(cur[0])
    if _age_min(info.get("ts", "1970-01-01T00:00:00+00:00")) > ttl and s3.put(key, body.encode(), if_match=cur[1]):
        return "won", who
    return "taken", info.get("who", "?")


def _read_json_bytes(b):
    try:
        return json.loads(b.decode("utf-8"))
    except ValueError:
        return {}


# ───────────────────────── контекст ─────────────────────────

def sync_context(s3):
    cache = HOME / "cache" / "context"
    texts = {}
    for key in s3.list("context/"):
        got = s3.get(key)
        if got is None:
            continue
        name = key[len("context/"):]
        texts[name] = got[0].decode("utf-8", "replace")
        _atomic_write(cache / name, texts[name])
    return texts


def cached_context():
    cache = HOME / "cache" / "context"
    if not cache.exists():
        return {}
    return {str(p.relative_to(cache)): p.read_text(encoding="utf-8") for p in sorted(cache.rglob("*")) if p.is_file()}


def _recent_keys(s3, root, limit):
    today = datetime.datetime.now(UTC)
    keys = []
    for d in (today - datetime.timedelta(days=1), today):
        keys += s3.list("%s/%s/" % (root, d.strftime("%Y-%m-%d")))
    return sorted(keys)[-limit:]


def recent_messages(s3, limit=6):
    lines = []
    for key in _recent_keys(s3, "messages", limit):
        got = s3.get(key)
        m = _read_json_bytes(got[0]) if got else {}
        if m:
            lines.append("- %s %s (%s): %s" % (m.get("ts", "")[5:16].replace("T", " "), m.get("who"), m.get("role"),
                                              " ".join(m.get("text", "").split())[:220]))
    return lines


def recent_events(s3, limit=15):
    lines = []
    for key in _recent_keys(s3, "events", limit):
        got = s3.get(key)
        ev = _read_json_bytes(got[0]) if got else {}
        if ev:
            lines.append("- %s %s %s%s: %s" % (ev.get("ts", "")[5:16].replace("T", " "), ev.get("who"), ev.get("kind"),
                                              " [%s]" % ev["task"] if ev.get("task") else "", ev.get("msg", "")[:160]))
    return lines


def active_claims(s3):
    lines = []
    for key in s3.list("claims/"):
        got = s3.get(key)
        info = _read_json_bytes(got[0]) if got else {}
        if info.get("ts") and _age_min(info["ts"]) <= CLAIM_TTL_MIN:
            lines.append("- %s: %s (%d мин назад)" % (info.get("task"), info.get("who"), _age_min(info["ts"])))
    return lines


def build_digest(s3):
    texts = sync_context(s3)
    state = s3.get("state.md")
    parts = ["# WorkHack: общий контекст из бакета (прочитан в начале сессии)", "", texts.get("core.md", "(core.md в бакете ещё нет)")]
    if state:
        parts += ["", "## Текущее состояние (state.md)", state[0].decode("utf-8", "replace")]
    others = sorted(n for n in texts if n != "core.md")
    if others:
        parts += ["", "## Другие файлы контекста (читай по теме: wh get context/<имя> -)"] + ["- " + n for n in others]
    parts += ["", "## Последние события"] + (recent_events(s3) or ["- (пока нет)"])
    parts += ["", "## Последние сообщения (журнал переписки, чтобы продолжить с места остановки)"] + (recent_messages(s3) or ["- (пока нет)"])
    parts += ["", "## Заняты сейчас (claim)"] + (active_claims(s3) or ["- (никто)"])
    parts += ["", "## Правило сессии", "Закончил работу: wh done \"что сделано + ссылки на файлы\" (или wh handoff / wh fail / wh note). Без записи итога сессию закрыть нельзя."]
    return "\n".join(parts)


def no_context_text(reason):
    cached = cached_context()
    out = ["!!! КОНТЕКСТА НЕТ: %s" % reason,
           "Скажи пользователю об этом сразу. Не работай вслепую и не выдумывай состояние. Запись итога встанет в очередь и уйдёт позже (wh flush)."]
    if cached.get("core.md"):
        out += ["", "Старая копия core.md из кэша (может быть устаревшей):", cached["core.md"]]
    return "\n".join(out)


def start_text():
    try:
        s3 = client(settings())
        flush_outbox(s3)
        return build_digest(s3)
    except (ConfigError, NetError, S3Error) as e:
        return no_context_text(e)


# ───────────────────────── команды ─────────────────────────

def cmd_setup(a):
    if a.from_env:
        pick = lambda n, d="": os.environ.get("WH_SETUP_" + n, d)  # noqa: E731
        vals = {"account_id": pick("ACCOUNT_ID"), "bucket": pick("BUCKET"), "jurisdiction": pick("JURISDICTION"),
                "who": pick("WHO", getpass.getuser()), "access_key_id": pick("ACCESS_KEY_ID"),
                "secret_access_key": pick("SECRET_ACCESS_KEY")}
    else:
        vals = {"account_id": input("Cloudflare Account ID: ").strip(), "bucket": input("Имя бакета: ").strip(),
                "jurisdiction": input("Юрисдикция [Enter = стандартная, eu, fedramp]: ").strip(),
                "who": input("Твоё имя для журнала (латиницей, напр. vlad): ").strip() or getpass.getuser(),
                "access_key_id": input("R2 Access Key ID: ").strip(),
                "secret_access_key": getpass.getpass("R2 Secret Access Key (ввод скрыт): ").strip()}
    gaps = missing(dict(vals, endpoint=""))
    if gaps:
        print("Не заполнено: %s" % ", ".join(gaps))
        return 1
    HOME.mkdir(parents=True, exist_ok=True)
    _atomic_write(HOME / "config.json", json.dumps({k: vals[k] for k in ("account_id", "bucket", "jurisdiction", "who")}, indent=2))
    _atomic_write(HOME / "credentials", json.dumps({k: vals[k] for k in ("access_key_id", "secret_access_key")}), 0o600)
    print("Настройки сохранены в %s (ключи: credentials, права 600). Проверь: wh doctor" % HOME)
    return 0


def _check(name, ok, detail=""):
    print("%s %s%s" % ("✓" if ok else "✗", name, (": " + detail) if detail else ""))
    return ok


def cmd_doctor(_):
    cfg = settings()
    gaps = missing(cfg)
    if gaps:
        print("✗ не хватает: %s. Запусти wh setup (или задай WH_* переменные)." % ", ".join(gaps))
        return 1
    s3 = client(cfg)
    key, ok = "_doctor/%s.txt" % secrets.token_hex(4), True
    try:
        ok &= _check("запись", s3.put(key, b"1", if_none_match=True))
        got = s3.get(key)
        ok &= _check("чтение", got is not None and got[0] == b"1")
        ok &= _check("If-None-Match (атомарный claim)", s3.put(key, b"2", if_none_match=True) is False,
                     "второй PUT на тот же ключ должен получить отказ")
        etag = got[1] if got else None
        ok &= _check("If-Match (перехват протухшего claim)", bool(etag) and s3.put(key, b"3", if_match=etag)
                     and s3.put(key, b"4", if_match=etag) is False)
        ok &= _check("список", key in s3.list("_doctor/"))
        s3.delete(key)
        ok &= _check("удаление", s3.head(key) is None)
    except (NetError, S3Error) as e:
        _check("соединение", False, str(e))
        ok = False
    print("Итог: %s" % ("всё работает" if ok else "есть проблемы, см. ✗ выше"))
    return 0 if ok else 1


def cmd_start(_):
    print(start_text())
    return 0


def cmd_log(a):
    state, where = record(a.kind, a.msg, a.task, a.file)
    print("записано: %s" % where if state == "ok" else "поставлено в очередь (отправится при следующем wh flush/start): %s" % where)
    return 0


def cmd_claim(a):
    cfg = settings()
    try:
        status, holder = claim(client(cfg), a.task, cfg["who"], a.ttl)
    except (ConfigError, NetError, S3Error) as e:
        print("не удалось проверить claim: %s" % e)
        return 3
    if status == "won":
        record("claim", "взял задачу", a.task)
        print("взял: %s" % a.task)
        return 0
    print(("уже закрыта (done): %s" % a.task) if status == "done" else "занято: %s (держит %s). Уступи." % (a.task, holder))
    return 2 if status == "done" else 1


def cmd_flush(_):
    try:
        print("отправлено из очереди: %d" % flush_outbox(client(settings())))
        return 0
    except (ConfigError, NetError, S3Error) as e:
        print("не вышло: %s" % e)
        return 1


def cmd_ls(a):
    print("\n".join(client(settings()).list(a.prefix)))
    return 0


def cmd_get(a):
    got = client(settings()).get(a.key)
    if got is None:
        print("нет такого ключа: %s" % a.key)
        return 1
    if a.dest == "-":
        print(got[0].decode("utf-8", "replace"))
    else:
        Path(a.dest).parent.mkdir(parents=True, exist_ok=True)
        Path(a.dest).write_bytes(got[0])
    return 0


def cmd_put(a):
    ok = client(settings()).put(a.key, Path(a.src).read_bytes(), if_none_match=not a.force)
    print("загружено: %s" % a.key if ok else "уже существует (используй --force): %s" % a.key)
    return 0 if ok else 1


def cmd_push_context(a):
    s3, root, sent, skipped = client(settings()), Path(a.dir), 0, 0
    for p in sorted(x for x in root.rglob("*") if x.is_file() and x.name != ".DS_Store"):
        ok = s3.put("context/" + p.relative_to(root).as_posix(), p.read_bytes(), if_none_match=not a.force)
        sent, skipped = sent + ok, skipped + (not ok)
    print("загружено: %d, пропущено (уже есть, живой контекст не трогаю): %d" % (sent, skipped))
    return 0


REPORT_FORMAT = """
---
## Формат ОТЧЁТА (в конце работы выдай именно такой блок, пользователь отправит его командой `wh ingest`)
ОТЧЁТ
- Что сделано: ...
- Файлы и ссылки: ...
- Что не доделано / решения, которые нужны от человека: ...
- Что запомнить на будущее: ...
"""


def cmd_pack(_):
    try:
        s3 = client(settings())
        flush_outbox(s3)
        texts, events = sync_context(s3), recent_events(s3)
    except (ConfigError, NetError, S3Error) as e:
        print("бакет недоступен (%s), собираю из кэша" % e)
        texts, events = cached_context(), []
    parts = ["# Пакет контекста WorkHack (для чата без доступа к бакету)",
             "Прочитай всё ниже как рабочий контекст. В конце работы выдай ОТЧЁТ в указанном формате.", ""]
    parts += ["## %s\n%s\n" % (n, t[:15000]) for n, t in sorted(texts.items(), key=lambda x: x[0] != "core.md")]
    parts += ["## Последние события"] + (events or ["- (нет данных)"]) + [REPORT_FORMAT]
    _atomic_write(HOME / "pack.md", "\n".join(parts))
    print("готово: %s (загрузи этот файл в чат)" % (HOME / "pack.md"))
    return 0


def cmd_config(a):
    if a.key not in CONFIG_KEYS or (CONFIG_KEYS[a.key] and a.value not in CONFIG_KEYS[a.key]) \
            or not re.fullmatch(r"[\w.-]+", a.value):
        allowed = {k: (list(v) if v else "любое имя") for k, v in CONFIG_KEYS.items()}
        print("можно менять только: %s" % allowed)
        return 1
    cfg = _read_json(HOME / "config.json")
    cfg[a.key] = a.value
    _atomic_write(HOME / "config.json", json.dumps(cfg, indent=2, ensure_ascii=False))
    print("%s = %s" % (a.key, a.value))
    return 0


BLOCK_BEGIN, BLOCK_END ="<!-- wh:begin -->", "<!-- wh:end -->"
AGENT_BLOCK = """%s
## Общая память WorkHack (обязательно, действует всегда)
1. Первое действие сессии: `wh start`, прочитать вывод целиком (в Claude Code это делает хук сам).
2. Перед задачей дня: `wh claim <задача>`. Ответ «занято» или «уже закрыта» = не делать.
3. Последнее действие: `wh done "что сделано + ссылки на файлы"` (или `wh handoff "причина + состояние"`, `wh fail`, `wh note`).
4. После каждого важного шага (опубликовал, сгенерировал, нашёл проблему) коротко: `wh note "..."`.
5. Секреты (токены, пароли, ключи, коды) никуда не записывать, в события тоже.
6. Если `wh` пишет «КОНТЕКСТА НЕТ»: сказать пользователю сразу, не работать вслепую.
%s
""" % (BLOCK_BEGIN, BLOCK_END)


def upsert_block(path):
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if BLOCK_BEGIN in old:
        head, _, rest = old.partition(BLOCK_BEGIN)
        new = head + AGENT_BLOCK.rstrip("\n") + rest.partition(BLOCK_END)[2]
    else:
        new = old + ("\n" if old and not old.endswith("\n") else "") + ("\n" if old else "") + AGENT_BLOCK
    if new != old:
        path.write_text(new, encoding="utf-8")


def cmd_init_project(a):
    root = Path(a.dir).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    (root / ".wh-project").touch()
    for name in ("CLAUDE.md", "AGENTS.md"):
        upsert_block(root / name)
    print("проект подключён: %s (маркер .wh-project, правила в CLAUDE.md и AGENTS.md)" % root)
    return 0


def cmd_ingest(a):
    text = Path(a.file).read_text(encoding="utf-8") if a.file else sys.stdin.read()
    state, where = record("report", text.strip()[:8000], a.task, suffix=a.source)
    print("записано: %s" % where if state == "ok" else "поставлено в очередь: %s" % where)
    return 0


# ───────────────────────── хуки Claude Code ─────────────────────────

def in_project(cwd):
    if os.environ.get("WH_ALWAYS") == "1":
        return True
    p = Path(cwd or os.getcwd()).resolve()
    return any((d / ".wh-project").exists() for d in [p] + list(p.parents))


def _emit(obj):
    print(json.dumps(obj, ensure_ascii=False))


def _marker(sid):
    return HOME / "sessions" / ("%s.started" % re.sub(r"[^\w.-]", "_", sid or "x"))


def hook_start(p):
    _atomic_write(_marker(p.get("session_id")), repr(time.time()))
    _emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": start_text()}})


def _closed_since(started):
    last = HOME / "last_close"
    return last.exists() and float(last.read_text()) >= started


def hook_prompt(p):
    record_message("user", p.get("prompt", ""), p.get("session_id"))


def _journal_reply(p):
    text = last_assistant_text(p.get("transcript_path"))
    seen = HOME / "sessions" / ("%s.lastreply" % re.sub(r"[^\w.-]", "_", p.get("session_id") or "x"))
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
    if text and (not seen.exists() or seen.read_text() != digest):  # Stop срабатывает дважды при блокировке
        record_message("assistant", text, p.get("session_id"))
        _atomic_write(seen, digest)


def hook_stop(p):
    try:
        _journal_reply(p)
    except Exception:  # журнал не должен мешать проверке итога
        pass
    m = _marker(p.get("session_id"))
    if p.get("stop_hook_active") or not m.exists() or _closed_since(float(m.read_text())):
        return
    _emit({"decision": "block", "reason": "Перед завершением запиши итог в общую память WorkHack: "
           "wh done \"что сделано + ссылки на файлы\" (или wh handoff \"причина и состояние\" / wh fail / wh note). "
           "После записи можно заканчивать."})


def hook_precompact(p):
    record("checkpoint", "Сжатие контекста (%s). Транскрипт: %s" % (p.get("trigger", "?"), p.get("transcript_path", "?")))


def hook_end(p):
    m = _marker(p.get("session_id"))
    if m.exists() and not _closed_since(float(m.read_text())):
        record("session-end", "Сессия закончилась без записанного итога (причина: %s). Транскрипт: %s"
               % (p.get("reason", "?"), p.get("transcript_path", "?")))
    if m.exists():
        m.unlink()


HOOKS = {"start": hook_start, "prompt": hook_prompt, "stop": hook_stop, "precompact": hook_precompact, "end": hook_end}


def cmd_hook(a):
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if in_project(payload.get("cwd")):
            HOOKS[a.name](payload)
    except Exception as e:  # хук не должен ронять сессию
        if a.name == "start":
            _emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": no_context_text("ошибка хука: %s" % e)}})
    return 0


# ───────────────────────── разбор аргументов ─────────────────────────

def build_parser():
    ap = argparse.ArgumentParser(prog="wh", description="Общая память WorkHack в R2")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        return sp

    add("setup", cmd_setup, "ввести данные R2 (ключи в ~/.workhack/credentials, права 600)").add_argument("--from-env", action="store_true")
    add("doctor", cmd_doctor, "проверить доступ, запись, чтение, атомарный claim")
    add("start", cmd_start, "в начале сессии: скачать и показать контекст")
    lg = add("log", cmd_log, "записать событие (также: wh done|handoff|fail|note \"текст\")")
    lg.add_argument("kind", choices=EVENT_KINDS)
    lg.add_argument("msg", nargs="?", default="")
    lg.add_argument("--task", default="")
    lg.add_argument("--file", action="append", default=[])
    cl = add("claim", cmd_claim, "взять задачу (0 взял, 1 занято, 2 уже done)")
    cl.add_argument("task")
    cl.add_argument("--ttl", type=int, default=CLAIM_TTL_MIN)
    add("flush", cmd_flush, "отправить накопленную очередь")
    add("ls", cmd_ls, "список ключей").add_argument("prefix", nargs="?", default="")
    g = add("get", cmd_get, "скачать ключ (dest = - печатает в экран)")
    g.add_argument("key")
    g.add_argument("dest", nargs="?", default="-")
    pt = add("put", cmd_put, "загрузить файл")
    pt.add_argument("src")
    pt.add_argument("key")
    pt.add_argument("--force", action="store_true")
    pc = add("push-context", cmd_push_context, "залить папку seed в context/ (существующее не трогает)")
    pc.add_argument("dir")
    pc.add_argument("--force", action="store_true")
    add("pack", cmd_pack, "собрать pack.md для чата без доступа к бакету (ChatGPT)")
    ig = add("ingest", cmd_ingest, "записать ОТЧЁТ из чата (файл или stdin)")
    ig.add_argument("file", nargs="?")
    ig.add_argument("--from", dest="source", default="chat")
    ig.add_argument("--task", default="")
    cf = add("config", cmd_config, "изменить настройку: wh config log_messages full|prompts|off")
    cf.add_argument("key")
    cf.add_argument("value")
    add("init-project", cmd_init_project, "подключить папку проекта: маркер + правила в CLAUDE.md/AGENTS.md").add_argument("dir")
    add("hook", cmd_hook, "служебное: вызов из хуков Claude Code").add_argument("name", choices=sorted(HOOKS))
    return ap


def main(argv):
    if argv and argv[0] in CLOSING:
        argv = ["log"] + argv
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except ConfigError as e:
        print(e)
        return 1
    except (NetError, S3Error) as e:
        print("ошибка связи с бакетом: %s" % e)
        return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv[1:]))
