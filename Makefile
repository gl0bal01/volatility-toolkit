PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
DOCDIR      ?= $(PREFIX)/share/doc/volatility-toolkit
BASHCOMPDIR ?= /etc/bash_completion.d
SCRIPT       = scripts/vol-analyze.sh
BIN_NAME     = vol-analyze

.PHONY: install uninstall lint check test help

help: ## Show this help
	@grep -E '^[a-z].*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Install binary, docs, and bash completions
	@install -d $(BINDIR) $(DOCDIR)
	@install -m 755 $(SCRIPT) $(BINDIR)/$(BIN_NAME)
	@install -m 644 docs/*.md $(DOCDIR)/
	@if [ -d $(BASHCOMPDIR) ]; then \
		install -m 644 completions/vol-analyze.bash $(BASHCOMPDIR)/$(BIN_NAME); \
		echo "Bash completions installed to $(BASHCOMPDIR)"; \
	fi
	@echo "Installed $(BIN_NAME) to $(BINDIR)"
	@echo "Docs installed to $(DOCDIR)"
	@echo ""
	@echo "Start a new shell or run: source $(BASHCOMPDIR)/$(BIN_NAME)"

uninstall: ## Remove installed files
	@rm -f $(BINDIR)/$(BIN_NAME)
	@rm -rf $(DOCDIR)
	@rm -f $(BASHCOMPDIR)/$(BIN_NAME)
	@echo "Uninstalled $(BIN_NAME)"

lint: ## Run shellcheck on the script
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not found — install: https://github.com/koalaman/shellcheck"; exit 1; }
	shellcheck $(SCRIPT)
	@echo "Lint passed"

test: ## Run unit tests
	@bash tests/test_vol_analyze.sh

check: ## Verify runtime dependencies
	@echo "Checking dependencies..."
	@command -v vol     >/dev/null 2>&1 && echo "  [ok] vol (Volatility 3)"   || echo "  [!!] vol (Volatility 3) — NOT FOUND"
	@command -v strings >/dev/null 2>&1 && echo "  [ok] strings"              || echo "  [!!] strings — NOT FOUND"
	@command -v md5sum  >/dev/null 2>&1 && echo "  [ok] md5sum"               || echo "  [!!] md5sum — NOT FOUND"
	@command -v sha256sum >/dev/null 2>&1 && echo "  [ok] sha256sum"          || echo "  [!!] sha256sum — NOT FOUND"
	@command -v grep    >/dev/null 2>&1 && echo "  [ok] grep"                 || echo "  [!!] grep — NOT FOUND"
	@bash --version | head -1
