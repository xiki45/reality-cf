#!/bin/bash
# REALITY-CF 安装脚本：优先就地虚拟环境安装，不污染系统 Python
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
REPO_URL="${REPO_URL:-https://github.com/xiki45/reality-cf.git}"

echo -e "${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}   REALITY-CF 节点发现 — 安装          ${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}"

# ── 1. Python 版本（代码需要 3.10+）──
PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            PY="$cand"; break
        fi
    fi
done
if [ -z "$PY" ]; then
    echo -e "${RED}✗ 需要 Python 3.10 或更新版本${NC}"
    echo "  macOS: brew install python@3.12   /   Linux: apt install python3.11 python3.11-venv"
    exit 1
fi
echo -e "${GREEN}✓${NC} 使用 $($PY -V)"

# ── 2. 定位项目目录：脚本在仓库内就就地安装，否则 clone ──
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/main.py" ]; then
    APP_DIR="$SRC_DIR"
    echo -e "${GREEN}✓${NC} 就地安装: $APP_DIR"
else
    APP_DIR="${INSTALL_DIR:-$HOME/.local/share/reality-cf}"
    if [ -d "$APP_DIR/.git" ]; then
        echo -e "${CYAN}→ 更新已有项目...${NC}"
        git -C "$APP_DIR" pull --ff-only || true
    else
        echo -e "${CYAN}→ 克隆到 $APP_DIR ...${NC}"
        mkdir -p "$(dirname "$APP_DIR")"
        git clone "$REPO_URL" "$APP_DIR"
    fi
fi

# ── 3. 虚拟环境 + 依赖 ──
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
    echo -e "${CYAN}→ 创建虚拟环境...${NC}"
    "$PY" -m venv "$APP_DIR/.venv"
fi
echo -e "${CYAN}→ 安装依赖...${NC}"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# ── 4. 注册命令 ──
mkdir -p "$BIN_DIR" 2>/dev/null || true
if [ -w "$BIN_DIR" ]; then
    cat > "$BIN_DIR/reality-cf" <<EOF
#!/bin/bash
exec "$APP_DIR/.venv/bin/python" "$APP_DIR/main.py" "\$@"
EOF
    chmod +x "$BIN_DIR/reality-cf"
    echo -e "${GREEN}✓${NC} 全局命令: $BIN_DIR/reality-cf"
else
    cat > "$APP_DIR/reality-cf" <<EOF
#!/bin/bash
exec "$APP_DIR/.venv/bin/python" "$APP_DIR/main.py" "\$@"
EOF
    chmod +x "$APP_DIR/reality-cf"
    echo -e "${YELLOW}!${NC} $BIN_DIR 不可写，命令生成在 $APP_DIR/reality-cf"
fi

# ── 5. 自检 ──
if "$APP_DIR/.venv/bin/python" -c "import cryptography, aiohttp, aiodns, colorama" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} 依赖自检通过"
else
    echo -e "${RED}✗ 依赖自检失败，请手动执行: $APP_DIR/.venv/bin/pip install -r $APP_DIR/requirements.txt${NC}"
    exit 1
fi

cat <<EOF

安装完成

  自备清单（最可靠）:
    reality-cf --sni images.apple.com --targets ips.txt --cf-domain your.domain.com
  账本目录:
    reality-cf --sni images.apple.com --ledger ./scans --cf-domain your.domain.com
  交互菜单:
    reality-cf

  可选: export SONAR_API_KEY=xxx 后加 --auto-ledger 自动下载 TLS 账本
  自测: cd $APP_DIR && .venv/bin/python tests/t_unit.py && .venv/bin/python tests/t_e2e.py
EOF
