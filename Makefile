.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: site
site:
	uv run --only-group docs zensical build --clean

.PHONY: site-live
site-live:
	uv run --only-group docs zensical serve

.PHONY: snippets
snippets: trophies sponsors
	cargo run -- -h > docs/snippets/help.txt

.PHONY: trophies
trophies: docs/snippets/trophies.md

docs/snippets/trophies.md: docs/snippets/trophies.txt docs/snippets/render-trophies.py
	docs/snippets/render-trophies.py > $@

.PHONY: sponsors
sponsors: docs/snippets/sponsors.html

docs/snippets/sponsors.html: docs/snippets/sponsors.json docs/snippets/render-sponsors.py
	docs/snippets/render-sponsors.py > $@

.PHONY: refresh-schemas
refresh-schemas:
	support/fetch-schemas.py

.PHONY: webhooks-to-contexts
webhooks-to-contexts:
	support/webhooks-to-contexts.py

.PHONY: codeql-injection-sinks
codeql-injection-sinks: crates/zizmor/data/codeql-injection-sinks.json

crates/zizmor/data/codeql-injection-sinks.json: support/codeql-injection-sinks.py
	$< > $@

.PHONY: sync-expression-tests
sync-expression-tests:
	support/sync-expression-tests.py

.PHONY: archived-repos
archived-repos:
	support/archived-repos.py

.PHONY: pinact
pinact:
	GITHUB_TOKEN=$$(gh auth token) pinact run --update --verify --config=.github/pinact.yml


.PHONY: bench
bench:
	uv run --only-group=bench pytest bench/ --codspeed

.PHONY: generate-schema
generate-schema:
	cargo run --features schema -- --generate-schema > support/zizmor.schema.json
