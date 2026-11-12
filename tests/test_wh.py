"""Тесты wh. Запуск: python3 -m unittest discover -s tests -v
Работают без сети и без реальных ключей: S3 подменяется локальным моком."""
import contextlib
import datetime
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
import wh  # noqa: E402

PAGE = 2  # мок отдаёт список по 2 ключа, чтобы проверять постраничность


class MockS3(BaseHTTPRequestHandler):
    store = {}   # key -> bytes
    down = False

    def log_message(self, *a):
        pass

    def _key(self):
        u = urllib.parse.urlsplit(self.path)
        parts = urllib.parse.unquote(u.path).lstrip("/").split("/", 1)
        return (parts[1] if len(parts) > 1 else ""), urllib.parse.parse_qs(u.query)

    def _etag(self, key):
        return '"%s"' % hashlib.md5(self.store[key]).hexdigest()

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _guard(self):
        if not self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "):
            self._send(403)
            return False
        return True

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        if not self._guard():
            return
        key, _ = self._key()
        if self.headers.get("If-None-Match") == "*" and key in self.store:
            return self._send(412)
        im = self.headers.get("If-Match")
        if im and (key not in self.store or self._etag(key) != im):
            return self._send(412)
        self.store[key] = data
        self._send(200, headers={"ETag": self._etag(key)})

    def do_GET(self):
        if not self._guard():
            return
        key, q = self._key()
        if key == "" and q.get("list-type") == ["2"]:
            prefix = q.get("prefix", [""])[0]
            keys = sorted(k for k in self.store if k.startswith(prefix))
            start = int(q.get("continuation-token", ["0"])[0])
            page = keys[start:start + PAGE]
            more = start + PAGE < len(keys)
            xml = "<ListBucketResult><IsTruncated>%s</IsTruncated>%s%s</ListBucketResult>" % (
                "true" if more else "false",
                "".join("<Contents><Key>%s</Key></Contents>" % k for k in page),
                "<NextContinuationToken>%d</NextContinuationToken>" % (start + PAGE) if more else "")
            return self._send(200, xml.encode())
        if key not in self.store:
            return self._send(404)
        self._send(200, self.store[key], {"ETag": self._etag(key)})

    do_HEAD = do_GET

    def do_DELETE(self):
        if not self._guard():
            return
        key, _ = self._key()
        self.store.pop(key, None)
        self._send(204)


class Base(unittest.TestCase):
    def setUp(self):
        MockS3.store = {}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), MockS3)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {
            "WH_HOME": self.tmp.name + "/home",
            "WH_ENDPOINT": "http://127.0.0.1:%d" % self.srv.server_port,
            "WH_BUCKET": "bkt", "WH_WHO": "tester",
            "WH_ACCESS_KEY_ID": "AKIDTEST", "WH_SECRET_ACCESS_KEY": "s3cr3t-value",
        }
        self._old = {k: os.environ.get(k) for k in list(self.env) + ["WH_ALWAYS", "WH_ACCOUNT_ID"]}
        os.environ.update(self.env)
        os.environ.pop("WH_ALWAYS", None)
        os.environ.pop("WH_ACCOUNT_ID", None)
        wh.HOME = Path(self.env["WH_HOME"])

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def run_wh(self, *argv, stdin=""):
        out = io.StringIO()
        old_in = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out):
                code = wh.main(list(argv))
        finally:
            sys.stdin = old_in
        return code, out.getvalue()

    def keys(self, prefix=""):
        return sorted(k for k in MockS3.store if k.startswith(prefix))


class TestSigV4(unittest.TestCase):
    def test_matches_aws_documented_example(self):
        # Пример из документации AWS S3 (GET Object с Range), ожидаемая подпись из неё же.
        h = wh.sign(
            "GET", "https://examplebucket.s3.amazonaws.com/test.txt",
            {"Range": "bytes=0-9"}, hashlib.sha256(b"").hexdigest(),
            "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1",
            now=datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc))
        self.assertIn(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            h["Authorization"])


class TestTls(unittest.TestCase):
    @unittest.skipUnless(os.path.exists("/etc/ssl/cert.pem"), "нужен системный файл сертификатов")
    def test_falls_back_to_system_ca_file_when_python_has_no_certs(self):
        import ssl
        from unittest import mock
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # как python.org-сборка без «Install Certificates»
        with mock.patch.object(wh.ssl, "create_default_context", return_value=empty):
            ctx = wh.ssl_context()
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)


class TestClient(Base):
    def s3(self):
        return wh.S3(self.env["WH_ENDPOINT"], "bkt", "AKIDTEST", "x")

    def test_roundtrip_conditional_list_delete(self):
        s = self.s3()
        self.assertTrue(s.put("a/1.txt", b"one", if_none_match=True))
        self.assertFalse(s.put("a/1.txt", b"two", if_none_match=True))
        self.assertEqual(s.get("a/1.txt")[0], b"one")
        self.assertIsNone(s.get("nope"))
        for i in range(2, 6):
            s.put("a/%d.txt" % i, b"x")
        self.assertEqual(s.list("a/"), ["a/%d.txt" % i for i in range(1, 6)])  # 5 ключей, 3 страницы
        s.delete("a/1.txt")
        self.assertIsNone(s.head("a/1.txt"))

    def test_rejects_unsigned_requests_so_mock_is_meaningful(self):
        import urllib.request
        with self.assertRaises(Exception):
            urllib.request.urlopen(self.env["WH_ENDPOINT"] + "/bkt/x")


class TestLog(Base):
    def test_log_writes_immutable_event(self):
        code, out = self.run_wh("log", "note", "сделал X", "--task", "daily-1")
        self.assertEqual(code, 0)
        (k,) = self.keys("events/")
        ev = json.loads(MockS3.store[k])
        self.assertEqual((ev["kind"], ev["who"], ev["task"], ev["msg"]), ("note", "tester", "daily-1", "сделал X"))

    def test_shortcut_and_secret_scrubbing(self):
        self.run_wh("done", "готово token=abcd1234efgh5678 и ключ " + "a1" * 23)
        (k,) = self.keys("events/")
        msg = json.loads(MockS3.store[k])["msg"]
        self.assertNotIn("abcd1234efgh5678", msg)
        self.assertNotIn("a1" * 23, msg)

    def test_offline_event_is_queued_then_flushed_once(self):
        os.environ["WH_ENDPOINT"] = "http://127.0.0.1:1"  # никто не слушает
        code, out = self.run_wh("log", "note", "без сети")
        self.assertEqual(code, 0)
        self.assertIn("очередь", out)
        self.assertEqual(self.keys("events/"), [])
        os.environ["WH_ENDPOINT"] = self.env["WH_ENDPOINT"]
        self.run_wh("flush")
        self.run_wh("flush")
        self.assertEqual(len(self.keys("events/")), 1)


class TestClaim(Base):
    def test_second_claim_loses_and_done_blocks_new_claims(self):
        self.assertEqual(self.run_wh("claim", "daily-1")[0], 0)
        code, out = self.run_wh("claim", "daily-1")
        self.assertEqual(code, 1)
        self.assertIn("tester", out)
        self.run_wh("done", "итог", "--task", "daily-1")
        self.assertEqual(self.run_wh("claim", "daily-1")[0], 2)

    def test_stale_claim_can_be_taken_over(self):
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=200)).isoformat()
        MockS3.store["claims/t.json"] = json.dumps({"task": "t", "who": "old", "ts": old}).encode()
        code, _ = self.run_wh("claim", "t")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(MockS3.store["claims/t.json"])["who"], "tester")


class TestStart(Base):
    def test_start_prints_core_state_events_and_claims(self):
        MockS3.store["context/core.md"] = "ПРАВИЛО-КОР".encode()
        MockS3.store["context/extra.md"] = b"x"
        MockS3.store["state.md"] = "СОСТОЯНИЕ".encode()
        self.run_wh("log", "note", "прошлое дело")
        self.run_wh("claim", "daily-9")
        code, out = self.run_wh("start")
        self.assertEqual(code, 0)
        for need in ("ПРАВИЛО-КОР", "СОСТОЯНИЕ", "прошлое дело", "daily-9", "extra.md"):
            self.assertIn(need, out)
        self.assertTrue((wh.HOME / "cache" / "context" / "core.md").exists())

    def test_start_without_access_says_so_instead_of_failing_silently(self):
        os.environ["WH_ENDPOINT"] = "http://127.0.0.1:1"
        code, out = self.run_wh("start")
        self.assertEqual(code, 0)
        self.assertIn("КОНТЕКСТА НЕТ", out)


class TestPack(Base):
    def test_pack_and_ingest_bridge_for_chat_without_shell(self):
        MockS3.store["context/core.md"] = "КОР".encode()
        code, out = self.run_wh("pack")
        self.assertEqual(code, 0)
        pack = (wh.HOME / "pack.md").read_text(encoding="utf-8")
        self.assertIn("КОР", pack)
        self.assertIn("ОТЧЁТ", pack)
        self.run_wh("ingest", "--from", "chatgpt", stdin="ОТЧЁТ: сделал 3 картинки")
        (k,) = self.keys("events/")
        ev = json.loads(MockS3.store[k])
        self.assertEqual((ev["kind"], ev["who"]), ("report", "tester+chatgpt"))
        self.assertIn("3 картинки", ev["msg"])


class TestHooks(Base):
    def project(self):
        p = Path(self.tmp.name) / "proj" / "sub"
        p.mkdir(parents=True)
        (p.parent / ".wh-project").write_text("")
        return str(p)

    def hook(self, name, **payload):
        return self.run_wh("hook", name, stdin=json.dumps(payload))

    def test_hooks_ignore_directories_outside_project(self):
        code, out = self.hook("start", session_id="s", cwd=self.tmp.name)
        self.assertEqual((code, out), (0, ""))

    def test_session_start_injects_context(self):
        MockS3.store["context/core.md"] = "КОР".encode()
        code, out = self.hook("start", session_id="s", cwd=self.project())
        data = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(data["hookEventName"], "SessionStart")
        self.assertIn("КОР", data["additionalContext"])

    def test_stop_blocks_until_summary_logged_then_allows(self):
        cwd = self.project()
        self.hook("start", session_id="s", cwd=cwd)
        _, out = self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=False)
        self.assertEqual(json.loads(out)["decision"], "block")
        self.run_wh("done", "итог")
        self.assertEqual(self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=False)[1], "")

    def test_stop_never_loops(self):
        cwd = self.project()
        self.hook("start", session_id="s", cwd=cwd)
        self.assertEqual(self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=True)[1], "")

    def test_session_end_writes_fallback_event_when_nothing_was_logged(self):
        cwd = self.project()
        self.hook("start", session_id="s", cwd=cwd)
        self.hook("end", session_id="s", cwd=cwd, reason="exit")
        kinds = [json.loads(MockS3.store[k])["kind"] for k in self.keys("events/")]
        self.assertEqual(kinds, ["session-end"])

    def test_precompact_checkpoints_state(self):
        cwd = self.project()
        self.hook("precompact", session_id="s", cwd=cwd, trigger="auto", transcript_path="/t.jsonl")
        (k,) = self.keys("events/")
        self.assertEqual(json.loads(MockS3.store[k])["kind"], "checkpoint")


class TestMessageJournal(TestHooks):
    """Каждое сообщение пользователя и ответ ИИ уходят в messages/ (отдельно от events/)."""

    def transcript(self, *replies):
        p = Path(self.tmp.name) / "t.jsonl"
        lines = [json.dumps({"type": "user", "message": {"role": "user", "content": "вопрос"}})]
        for r in replies:
            lines.append(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash", "input": {}}, {"type": "text", "text": r}]}}))
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)

    def messages(self):
        return [json.loads(MockS3.store[k]) for k in self.keys("messages/")]

    def test_prompt_hook_journals_user_message_scrubbed_and_prints_nothing(self):
        code, out = self.hook("prompt", session_id="s", cwd=self.project(), prompt="сделай пост token=abc123def456ghi789")
        self.assertEqual((code, out), (0, ""))
        (m,) = self.messages()
        self.assertEqual((m["role"], m["session"]), ("user", "s"))
        self.assertIn("сделай пост", m["text"])
        self.assertNotIn("abc123def456ghi789", m["text"])

    def test_stop_journals_last_assistant_text_once_even_when_it_blocks_then_allows(self):
        cwd, tp = self.project(), self.transcript("первый ответ", "итоговый ответ")
        self.hook("start", session_id="s", cwd=cwd)
        self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=False, transcript_path=tp)   # блокирует
        self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=True, transcript_path=tp)    # разрешает
        got = self.messages()
        self.assertEqual([(m["role"], m["text"]) for m in got], [("assistant", "итоговый ответ")])

    def test_modes_prompts_only_and_off(self):
        cwd, tp = self.project(), self.transcript("ответ")
        os.environ["WH_LOG_MESSAGES"] = "prompts"
        try:
            self.hook("prompt", session_id="s", cwd=cwd, prompt="вопрос")
            self.hook("stop", session_id="s", cwd=cwd, stop_hook_active=True, transcript_path=tp)
            self.assertEqual([m["role"] for m in self.messages()], ["user"])
            os.environ["WH_LOG_MESSAGES"] = "off"
            self.hook("prompt", session_id="s", cwd=cwd, prompt="ещё вопрос")
            self.assertEqual(len(self.messages()), 1)
        finally:
            os.environ.pop("WH_LOG_MESSAGES")

    def test_message_is_queued_offline_and_start_digest_shows_recent_messages(self):
        cwd = self.project()
        os.environ["WH_ENDPOINT"] = "http://127.0.0.1:1"
        self.hook("prompt", session_id="s", cwd=cwd, prompt="сообщение без сети")
        self.assertEqual(self.keys("messages/"), [])
        os.environ["WH_ENDPOINT"] = self.env["WH_ENDPOINT"]
        self.run_wh("flush")
        code, out = self.run_wh("start")
        self.assertIn("Последние сообщения", out)
        self.assertIn("сообщение без сети", out)

    def test_config_command_accepts_only_known_keys(self):
        self.assertEqual(self.run_wh("config", "log_messages", "prompts")[0], 0)
        self.assertEqual(json.loads((wh.HOME / "config.json").read_text())["log_messages"], "prompts")
        self.assertEqual(self.run_wh("config", "log_messages", "всё-подряд")[0], 1)
        self.assertEqual(self.run_wh("config", "secret_access_key", "x")[0], 1)


class TestWhCodex(Base):
    def test_wrapper_injects_context_into_codex_prompt_and_logs_session_end(self):
        import subprocess
        fake = Path(self.tmp.name) / "fakebin"
        fake.mkdir()
        out_file = Path(self.tmp.name) / "codex_args.txt"
        (fake / "codex").write_text('#!/bin/sh\nprintf "%s" "$*" > "' + str(out_file) + '"\n', encoding="utf-8")
        (fake / "codex").chmod(0o755)
        MockS3.store["context/core.md"] = "КОР-ДЛЯ-КОДЕКС".encode()
        env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"])
        root = Path(__file__).resolve().parent.parent / "bin"
        res = subprocess.run([str(root / "wh-codex"), "сделай пост"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        sent = out_file.read_text(encoding="utf-8")
        self.assertIn("КОР-ДЛЯ-КОДЕКС", sent)
        self.assertIn("сделай пост", sent)
        kinds = [json.loads(MockS3.store[k])["kind"] for k in self.keys("events/")]
        self.assertEqual(kinds, ["session-end"])


class TestInitProject(Base):
    def test_init_project_is_idempotent_and_keeps_existing_text(self):
        d = Path(self.tmp.name) / "wp"
        d.mkdir()
        (d / "CLAUDE.md").write_text("# Мои правила\nне трогать\n", encoding="utf-8")
        for _ in range(2):
            self.assertEqual(self.run_wh("init-project", str(d))[0], 0)
        text = (d / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("не трогать", text)
        self.assertEqual(text.count("wh start"), 1)
        self.assertTrue((d / "AGENTS.md").exists())
        self.assertTrue((d / ".wh-project").exists())
        (d / "sub").mkdir()
        self.assertTrue(wh.in_project(str(d / "sub")))


class TestSetupDoctorSeed(Base):
    def test_setup_from_env_writes_private_files_and_doctor_passes(self):
        for k in ("WH_BUCKET", "WH_ACCESS_KEY_ID", "WH_SECRET_ACCESS_KEY"):
            os.environ.pop(k)
        os.environ.update({"WH_SETUP_BUCKET": "bkt", "WH_SETUP_ACCOUNT_ID": "acc",
                           "WH_SETUP_ACCESS_KEY_ID": "AKIDTEST", "WH_SETUP_SECRET_ACCESS_KEY": "zzz",
                           "WH_SETUP_WHO": "vlad"})
        try:
            code, out = self.run_wh("setup", "--from-env")
        finally:
            for k in [k for k in os.environ if k.startswith("WH_SETUP_")]:
                os.environ.pop(k)
        self.assertEqual(code, 0)
        self.assertNotIn("zzz", out)
        cred = wh.HOME / "credentials"
        self.assertEqual(oct(cred.stat().st_mode & 0o777), "0o600")
        self.assertEqual(json.loads((wh.HOME / "config.json").read_text())["who"], "vlad")
        os.environ.update({"WH_BUCKET": "bkt", "WH_ENDPOINT": self.env["WH_ENDPOINT"]})
        code, out = self.run_wh("doctor")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.keys("_doctor/"), [])  # за собой убрал

    def test_doctor_names_missing_settings(self):
        os.environ.pop("WH_BUCKET")
        code, out = self.run_wh("doctor")
        self.assertEqual(code, 1)
        self.assertIn("bucket", out)

    def test_push_context_does_not_overwrite_shared_context_without_force(self):
        seed = Path(self.tmp.name) / "seed"
        seed.mkdir()
        (seed / "core.md").write_text("СИД", encoding="utf-8")
        MockS3.store["context/core.md"] = "ЖИВОЙ".encode()
        self.run_wh("push-context", str(seed))
        self.assertEqual(MockS3.store["context/core.md"], "ЖИВОЙ".encode())
        self.run_wh("push-context", str(seed), "--force")
        self.assertEqual(MockS3.store["context/core.md"], "СИД".encode())


if __name__ == "__main__":
    unittest.main()
