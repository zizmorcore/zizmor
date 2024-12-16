.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: site
site: site-requirements.txt
	uvx --with-requirements $< mkdocs build

.PHONY: site-live
site-live: site-requirements.txt
	uvx --with-requirements $< mkdocs serve

.PHONY: snippets
snippets: trophies
	cargo run -- -h > docs/snippets/help.txt

.PHONY: trophies
trophies: docs/snippets/trophies.md

docs/snippets/trophies.md: docs/snippets/trophies.txt docs/snippets/render-trophies.py
	uv run --no-project docs/snippets/render-trophies.py > $@
