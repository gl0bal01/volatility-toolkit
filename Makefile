PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
DOCDIR      ?= $(PREFIX)/share/doc/volatility-toolkit
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR  ?= $(PREFIX)/share/zsh/site-functions
# The script finds the TLD list at <its dir>/../share/volatility-toolkit.
DATADIR      = $(BINDIR)/../share/volatility-toolkit
TLDS         = share/volatility-toolkit/tlds.txt
SCRIPT       = scripts/vol-analyze.sh
BIN_NAME     = vol-analyze
SHELL_FILES  = $(SCRIPT) tests/test_vol_analyze.sh completions/vol-analyze.bash scripts/ci-local.sh scripts/real-dump-test.sh .githooks/pre-push

.PHONY: install uninstall lint check test ci ci-real real-test hooks update-tlds check-tlds help

help: ## Show this help
	@grep -E '^[a-z].*:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Install binary, docs, and shell completions (supports DESTDIR)
	@install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR) $(DESTDIR)$(DOCDIR) $(DESTDIR)$(BASHCOMPDIR) $(DESTDIR)$(ZSHCOMPDIR)
	@install -m 755 $(SCRIPT) $(DESTDIR)$(BINDIR)/$(BIN_NAME)
	@install -m 644 $(TLDS) $(DESTDIR)$(DATADIR)/
	@install -m 644 docs/*.md $(DESTDIR)$(DOCDIR)/
	@install -m 644 completions/vol-analyze.bash $(DESTDIR)$(BASHCOMPDIR)/$(BIN_NAME)
	@install -m 644 completions/vol-analyze.zsh $(DESTDIR)$(ZSHCOMPDIR)/_$(BIN_NAME)
	@echo "Installed $(BIN_NAME) to $(DESTDIR)$(BINDIR)"
	@echo "Docs installed to $(DESTDIR)$(DOCDIR)"
	@echo "Completions installed to $(DESTDIR)$(BASHCOMPDIR) and $(DESTDIR)$(ZSHCOMPDIR) (start a new shell)"

uninstall: ## Remove installed files
	@rm -f $(DESTDIR)$(BINDIR)/$(BIN_NAME) $(DESTDIR)$(DATADIR)/$(notdir $(TLDS))
	@rmdir $(DESTDIR)$(DATADIR) 2>/dev/null || true
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

ci-real: ## Run the CI steps plus the monthly real-dumps workflow (~2 GB download)
	@bash scripts/ci-local.sh --real

real-test: ## Run vol-analyze with the real Volatility 3 on public memory images
	@bash scripts/real-dump-test.sh

hooks: ## Run make ci before every git push (once per clone)
	git config core.hooksPath .githooks

update-tlds: ## Refresh the IANA TLD list used for domain IOCs
	curl -fsSL https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o $(TLDS).tmp \
		&& grep -qx COM $(TLDS).tmp && mv $(TLDS).tmp $(TLDS) || { rm -f $(TLDS).tmp; exit 1; }
	@head -1 $(TLDS)

check-tlds: ## Fail if IANA's TLD list changed since the last update-tlds
	@tmp=$$(mktemp) && trap 'rm -f "$$tmp"' EXIT; \
		curl -fsSL https://data.iana.org/TLD/tlds-alpha-by-domain.txt | grep -v '^#' > "$$tmp"; \
		grep -qx COM "$$tmp" || { echo "Could not download IANA's TLD list"; exit 1; }; \
		if grep -v '^#' $(TLDS) | diff -u - "$$tmp"; then echo "TLD list is current"; \
		else echo "TLD list is stale: run make update-tlds"; exit 1; fi

check: ## Verify runtime dependencies
	@echo "Checking dependencies..."
	@command -v vol     >/dev/null 2>&1 && echo "  [ok] vol (Volatility 3)"   || echo "  [!!] vol (Volatility 3) — NOT FOUND"
	@command -v strings >/dev/null 2>&1 && echo "  [ok] strings"              || echo "  [!!] strings — NOT FOUND"
	@command -v md5sum  >/dev/null 2>&1 && echo "  [ok] md5sum"               || { command -v md5    >/dev/null 2>&1 && echo "  [ok] md5 (BSD)"    || echo "  [!!] md5sum/md5 — NOT FOUND"; }
	@command -v sha256sum >/dev/null 2>&1 && echo "  [ok] sha256sum"          || { command -v shasum >/dev/null 2>&1 && echo "  [ok] shasum (BSD)" || echo "  [!!] sha256sum/shasum — NOT FOUND"; }
	@command -v grep    >/dev/null 2>&1 && echo "  [ok] grep"                 || echo "  [!!] grep — NOT FOUND"
	@command -v fold    >/dev/null 2>&1 && echo "  [ok] fold"                 || echo "  [!!] fold — NOT FOUND"
	@command -v iconv   >/dev/null 2>&1 && echo "  [ok] iconv"                || echo "  [--] iconv — optional, JSON-escapes non-UTF-8 paths"
	@bash --version | head -1
