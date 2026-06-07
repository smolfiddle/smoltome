# ══════════════════════════════════════════════════════════════════════════════
# Makefile for smoltome (Explicit Script Invocation & Directory Auto-Scanning)
# ══════════════════════════════════════════════════════════════════════════════

# Core Variables
PYTHON       := python3
SRC          := smoltome.py
DEFAULT_PORT := 8080
DEFAULT_VLT  := library.vault

.PHONY: all help convert serve clean

all: help

help:
	@echo "smoltome Current-Directory Automation Workflows"
	@echo "=================================================="
	@echo "Execution Subcommands:"
	@echo "  make convert     - Pack all local .epub files directly into $(DEFAULT_VLT)"
	@echo "  make serve       - Scan local dir for the first .vault file and boot web reader"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean       - Strip temporary cache structures and bytecode buffers"

convert:
	@echo "Scanning current directory for EPUB files..."
	@# Verify that there is at least one .epub file before invoking
	@if [ -n "$$(ls *.epub 2>/dev/null)" ]; then \
		echo "Found EPUBs. Passing current directory context down to script..."; \
		$(PYTHON) $(SRC) convert --vault $(DEFAULT_VLT) --epub-dir . ; \
	else \
		echo "Error: No .epub files discovered in the current directory."; \
		exit 1; \
	fi

serve:
	@echo "Scanning current directory for active database vaults..."
	@# Find the first .vault file available in the local directory
	@VAULT_FILE=$$(ls *.vault 2>/dev/null | head -n 1); \
	if [ -n "$$VAULT_FILE" ]; then \
		echo "Discovered vault: $$VAULT_FILE"; \
		echo "Booting web reader environment on port $(DEFAULT_PORT)..."; \
		$(PYTHON) $(SRC) read --port $(DEFAULT_PORT) --vault "$$VAULT_FILE"; \
	else \
		echo "Error: No matching .vault index stores found in this directory."; \
		echo "Please execute 'make convert' first to compile your libraries."; \
		exit 1; \
	fi

clean:
	@echo "Removing generated environment runtime structures..."
	rm -rf __pycache__ .mypy_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
