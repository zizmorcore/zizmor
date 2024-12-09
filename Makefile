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
snippets:
	cargo run -- -h > docs/snippets/help.txt
