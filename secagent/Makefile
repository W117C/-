.PHONY: install test server clean reverse help update-templates health-check lint

help:
	@echo "SecAgent 工作流"
	@echo "  make install          — 安装依赖 + 二进制工具"
	@echo "  make test             — 运行全部测试"
	@echo "  make lint             — 快速测试 + 导入检查"
	@echo "  make server           — 启动 MCP 服务器"
	@echo "  make reverse          — 运行所有逆向分析脚本"
	@echo "  make update-templates — 更新 Nuclei 模板"
	@echo "  make health-check     — 检查所有二进制工具和模板状态"
	@echo "  make clean            — 清理缓存"

install:
	pip install -e ".[mcp]"
	bash scripts/install.sh
	make update-templates

test:
	python -m pytest tests/ -v --tb=short

lint:
	python -m pytest tests/ --tb=short -q
	@python -c "import secagent; print('✅ imports OK', secagent.__version__)"

server:
	python -m secagent.server

update-templates:
	@echo "=== 更新 Nuclei 模板 ==="
	@if [ -f ./bin/nuclei ]; then \
		./bin/nuclei -update-templates 2>/dev/null && echo "✅ 模板更新完成" || echo "⚠️ 模板更新失败，扫描将使用已有模板"; \
	else \
		echo "⚠️ nuclei 未安装，跳过模板更新"; \
	fi

health-check:
	@echo "=== SecAgent 健康检查 ==="
	@echo "--- 二进制工具 ---"
	@for tool in subfinder httpx nuclei gitleaks naabu ffuf katana dnsx tlsx uncover; do \
		if [ -f ./bin/$$tool ]; then \
			V=$$(./bin/$$tool -version 2>&1 | head -1); \
			echo "  ✅ $$tool: $$V"; \
		else \
			echo "  ❌ $$tool: 未安装 (运行 make install)"; \
		fi; \
	done
	@echo "--- Nuclei 模板 ---"
	@if [ -f ./bin/nuclei ]; then \
		./bin/nuclei -tl 2>&1 | tail -1 | grep -oP '\d+ Templates' && echo "✅ 模板已安装" || echo "⚠️ 模板未安装 (运行 make update-templates)"; \
	else \
		echo "  ⚠️ nuclei 未安装"; \
	fi
	@echo "--- 字典文件 ---"
	@for wl in wordlists/paths_builtin.txt wordlists/common.txt; do \
		if [ -f ./$$wl ]; then echo "  ✅ $$wl"; else echo "  ❌ $$wl: 缺失"; fi; \
	done
	@echo "--- Python 依赖 ---"
	@python -c "import secagent; print('  ✅ secagent', secagent.__version__)" 2>/dev/null || echo "  ❌ secagent 未安装"
	@python -c "import mcp; print('  ✅ MCP SDK OK')" 2>/dev/null || echo "  ❌ MCP SDK 未安装 (pip install -e .[mcp])"

reverse:
	@echo "=== Bilibili 逆向 ===" && python scripts/reverse/reverse_bilibili.py
	@echo "=== Codex 逆向 ===" && python scripts/reverse/reverse_codex.py
	@echo "=== Claude 检测分析 ===" && python scripts/reverse/analyze_claude_detection.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
