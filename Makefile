PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
DOCDIR      ?= $(PREFIX)/share/doc/volatility-toolkit
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR  ?= $(PREFIX)/share/zsh/site-functions
SCRIPT       = scripts/vol-analyze.sh
BIN_NAME     = vol-analyze
SHELL_FILES  = $(SCRIPT) tests/test_vol_analyze.sh completions/vol-analyze.bash scripts/ci-local.sh

.PHONY: install uninstall lint check test ci help

help: ## Show this help
	@grep -E '^[a-z].*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Install binary, docs, and shell completions (supports DESTDIR)
	@install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DOCDIR) $(DESTDIR)$(BASHCOMPDIR) $(DESTDIR)$(ZSHCOMPDIR)
	@install -m 755 $(SCRIPT) $(DESTDIR)$(BINDIR)/$(BIN_NAME)
	@install -m 644 docs/*.md $(DESTDIR)$(DOCDIR)/
	@install -m 644 completions/vol-analyze.bash $(DESTDIR)$(BASHCOMPDIR)/$(BIN_NAME)
	@install -m 644 completions/vol-analyze.zsh $(DESTDIR)$(ZSHCOMPDIR)/_$(BIN_NAME)
	@echo "Installed $(BIN_NAME) to $(DESTDIR)$(BINDIR)"
	@echo "Docs installed to $(DESTDIR)$(DOCDIR)"
	@echo "Completions installed to $(DESTDIR)$(BASHCOMPDIR) and $(DESTDIR)$(ZSHCOMPDIR) (start a new shell)"

uninstall: ## Remove installed files
	@rm -f $(DESTDIR)$(BINDIR)/$(BIN_NAME)
	@rm -f $(addprefix $(DESTDIR)$(DOCDIR)/,$(notdir $(wildcard docs/*.md)))
	@rmdir $(DESTDIR)$(DOCDIR) 2>/dev/null || true
	@rm -f $(DESTDIR)$(BASHCOMPDIR)/$(BIN_NAME) $(DESTDIR)$(ZSHCOMPDIR)/_$(BIN_NAME)
	@echo "Uninstalled $(BIN_NAME)"

lint: ## Syntax-check and shellcheck all shell files
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not found — install: https://github.com/koalaman/shellcheck"; exit 1; }
	bash -n $(SCRIPT)
	bash -n completions/vol-analyze.bash
	zsh -n completions/vol-analyze.zsh
	shellcheck -x $(SHELL_FILES)
	@echo "Lint passed"

test: ## Run unit and end-to-end tests
	@bash tests/test_vol_analyze.sh

ci: ## Run every CI step locally (same steps as .github/workflows/lint.yml)
	@bash scripts/ci-local.sh

check: ## Verify runtime dependencies
	@echo "Checking dependencies..."
	@command -v vol     >/dev/null 2>&1 && echo "  [ok] vol (Volatility 3)"   || echo "  [!!] vol (Volatility 3) — NOT FOUND"
	@command -v strings >/dev/null 2>&1 && echo "  [ok] strings"              || echo "  [!!] strings — NOT FOUND"
	@command -v md5sum  >/dev/null 2>&1 && echo "  [ok] md5sum"               || { command -v md5    >/dev/null 2>&1 && echo "  [ok] md5 (BSD)"    || echo "  [!!] md5sum/md5 — NOT FOUND"; }
	@command -v sha256sum >/dev/null 2>&1 && echo "  [ok] sha256sum"          || { command -v shasum >/dev/null 2>&1 && echo "  [ok] shasum (BSD)" || echo "  [!!] sha256sum/shasum — NOT FOUND"; }
	@command -v grep    >/dev/null 2>&1 && echo "  [ok] grep"                 || echo "  [!!] grep — NOT FOUND"
	@bash --version | head -1
