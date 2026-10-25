#!/bin/bash
# 一键跑全部离线测试（单元 / 端到端 / CLI）
set -u
cd "$(dirname "$0")/.." || exit 1
PY="${PY:-.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"
fail=0
for t in t_unit t_e2e t_cli; do
    echo "========== $t =========="
    "$PY" "tests/$t.py" || fail=1
    echo
done
[ $fail -eq 0 ] && echo "全部通过" || echo "有失败项"
exit $fail
