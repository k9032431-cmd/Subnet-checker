#!/data/data/com.termux/files/usr/bin/bash
# Установка subcheck в Termux: после этого команда `subcheck` доступна отовсюду.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${PREFIX:-/usr/local}/bin"
command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 || pkg install -y python
install -m 755 "$DIR/subcheck.py" "$BIN/subcheck"
echo "Готово. Запуск: subcheck"
