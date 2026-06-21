#!/bin/bash
# link-binaries.sh — 把 brew/系统安装好的安全工具软链到 secagent/bin/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/../bin" && pwd)"

mkdir -p "$BIN_DIR"

echo "=== 软链安全工具到 $BIN_DIR ==="

link_one() {
    local name="$1"
    local src="$2"
    if [ ! -f "$src" ]; then
        echo "  ✗ $name: 源文件不存在 $src"
        return 1
    fi
    # 如果已有文件且不是软链，备份
    local dst="$BIN_DIR/$name"
    if [ -f "$dst" ] && [ ! -L "$dst" ]; then
        cp "$dst" "$dst.bak.$(date +%s)"
        echo "  ⚠ $name: 已有二进制，已备份"
    fi
    rm -f "$dst"
    ln -sf "$src" "$dst"
    # 验证
    if "$dst" version >/dev/null 2>&1 || "$dst" --version >/dev/null 2>&1 || "$dst" -version >/dev/null 2>&1 || "$dst" -h >/dev/null 2>&1; then
        echo "  ✓ $name → $src"
    else
        echo "  ⚠ $name → $src (软链成功，但无法验证版本)"
    fi
}

# 1. 从 brew 安装的路径来找
if command -v brew &>/dev/null; then
    BREW_PREFIX=$(brew --prefix)

    # projectdiscovery tools (可能从 projectdiscovery/tap 或默认 formula)
    for name in subfinder nuclei; do
        # 先查 brew 安装路径
        src=$(brew list "$name" 2>/dev/null | grep -E "bin/$name$" | head -1 || echo "")
        if [ -z "$src" ]; then
            # 尝试 projectdiscovery/tap 路径
            src="$BREW_PREFIX/bin/$name"
        fi
        if [ -f "$src" ]; then
            link_one "$name" "$src"
        else
            echo "  ✗ $name: 未找到 (brew 可能还在安装或者需要 projectdiscovery/tap)"
        fi
    done

    # gitleaks — brew 安装的或已有的
    src="$BREW_PREFIX/bin/gitleaks"
    if [ -f "$src" ]; then
        link_one "gitleaks" "$src"
    else
        echo "  - gitleaks: brew 路径未找到，保留 bin/ 里已有的"
    fi

    # httpx — 必须是 projectdiscovery 的，不是 Python 的
    # projectdiscovery httpx 是 Go 二进制，特征：file 输出含 "Mach-O"
    for candidate in "$BREW_PREFIX/bin/httpx" "$BREW_PREFIX/bin/pd-httpx"; do
        if [ -f "$candidate" ] && file "$candidate" | grep -qi "mach-o"; then
            link_one "httpx" "$candidate"
            break
        fi
    done
fi

echo ""
echo "=== 验证 ==="
for t in subfinder httpx nuclei gitleaks; do
    p="$BIN_DIR/$t"
    if [ -f "$p" ] && [ -x "$p" ]; then
        echo "  ✓ $t: $(file "$p" | cut -d: -f2-)"
    else
        echo "  ✗ $t: 缺失"
    fi
done
