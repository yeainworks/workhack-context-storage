#!/usr/bin/env bash
# Установка общей памяти WorkHack на этот Mac/Linux.
#   bash install.sh [--project ПАПКА_ПРОЕКТА_WORKHACK] [--no-plugin]
# Идемпотентно: повторный запуск безопасен.
# Коды выхода: 0 готово · 10 нужно ввести данные R2 (wh setup в терминале человека) · 11 doctor не прошёл · 2 ошибка запуска
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
PROJECT=""; NOPLUGIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="${2:?нужен путь}"; shift 2 ;;
    --no-plugin) NOPLUGIN=1; shift ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "неизвестный аргумент: $1"; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
WH="$REPO/bin/wh"

say "1/6 Python"
command -v python3 >/dev/null 2>&1 || { echo "Нужен python3 (3.9+). Mac: xcode-select --install или brew install python"; exit 2; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' || { echo "Нужен Python 3.9+"; exit 2; }
chmod +x "$REPO/bin/wh" "$REPO/bin/wh.py"

say "2/6 Команда wh в ~/.local/bin"
mkdir -p "$HOME/.local/bin"
printf '#!/bin/sh\nexec "%s" "$@"\n' "$WH" > "$HOME/.local/bin/wh"
chmod +x "$HOME/.local/bin/wh"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "~/.local/bin нет в PATH. Добавь в ~/.zshrc строку:  export PATH=\"\$HOME/.local/bin:\$PATH\"  (до этого пользуюсь полным путём $WH)" ;;
esac

say "3/6 Данные R2"
HOME_DIR="${WH_HOME:-$HOME/.workhack}"
if [ -f "$HOME_DIR/config.json" ] && [ -f "$HOME_DIR/credentials" ]; then
  echo "уже настроено: $HOME_DIR"
elif [ -n "${WH_SETUP_BUCKET:-}" ]; then
  "$WH" setup --from-env
elif [ -t 0 ]; then
  "$WH" setup
else
  echo "NEED_SETUP: нужны Account ID, имя бакета, Access Key ID и Secret Access Key от R2."
  echo "Человек вводит их САМ в терминале: wh setup  (секрет в чат не писать). Потом снова bash install.sh"
  exit 10
fi

say "4/6 Проверка доступа (doctor)"
"$WH" doctor || { echo "doctor не прошёл: см. таблицу «Если не работает» в INSTALL.md"; exit 11; }

say "5/6 Начальный контекст"
if [ -z "$("$WH" ls context/ | head -1)" ]; then
  "$WH" push-context "$REPO/seed/context"
else
  echo "в бакете контекст уже есть, не трогаю"
fi

say "6/6 Подключение проекта и плагина Claude Code"
if [ -n "$PROJECT" ]; then "$WH" init-project "$PROJECT"; else echo "папка проекта не указана (--project): хуки Claude Code работают только внутри проекта с маркером .wh-project"; fi
if [ "$NOPLUGIN" = 0 ] && command -v claude >/dev/null 2>&1; then
  claude plugin marketplace add "$REPO" || echo "(маркетплейс уже добавлен или команда недоступна)"
  claude plugin install workhack-context@workhack-context-storage || echo "(плагин уже установлен или нужна ручная установка: см. INSTALL.md, раздел «Плагин»)"
else
  echo "плагин пропущен (нет claude CLI или --no-plugin)"
fi
say "ГОТОВО. Дальше: docs/USAGE.md"
