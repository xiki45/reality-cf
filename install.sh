#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   REALITY-CF 漏洞精准抓取 — 安装器  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo

INSTALL_DIR="/opt/reality-cf"
BIN_DIR="/usr/local/bin"

# 1. 检查 Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}❌ 需要 Python 3.10+，请先安装${NC}"
    exit 1
fi
PYVER=$(python3 -c 'import sys; print(sys.version_info.minor)')
echo -e "${GREEN}✓${NC} Python 3.$PYVER"

# 2. 安装依赖
echo -e "${CYAN}→ 安装 Python 依赖...${NC}"
pip3 install cryptography aiodns colorama aiohttp 2>&1 | tail -1

# 3. 克隆项目
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${CYAN}→ 更新已有项目...${NC}"
    cd "$INSTALL_DIR" && git pull --ff-only 2>/dev/null || true
else
    echo -e "${CYAN}→ 克隆项目...${NC}"
    git clone https://github.com/e13815332/reality-cf.git "$INSTALL_DIR"
fi

# 4. 注册全局命令
cat > "$BIN_DIR/reality-cf" << 'CMDENDS'
#!/bin/bash
cd /opt/reality-cf && exec python3 main.py "$@"
CMDENDS
chmod +x "$BIN_DIR/reality-cf"

echo
echo -e "${GREEN}✅ 安装完成！${NC}"
echo
echo -e "  快速开始:"
echo -e "    ${CYAN}reality-cf --sni images.apple.com --cf-domain your.domain.com${NC}"
echo
echo -e "  交互模式:"
echo -e "    ${CYAN}reality-cf${NC}"
echo
echo -e "  更新:"
echo -e "    ${CYAN}curl -fsSL https://raw.githubusercontent.com/e13815332/reality-cf/main/install.sh | bash${NC}"
