VENV = .venv
VENV_BIN := $(VENV)/bin

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: site
site: $(VENV)
	$(VENV_BIN)/mkdocs build

.PHONY: site-live
site-live: $(VENV)
	$(VENV_BIN)/mkdocs serve

$(VENV): site-requirements.txt
	uv venv
	uv pip install -r site-requirements.txt

.PHONY: snippets
snippets:
	cargo run -- -h > docs/snippets/help.txt
