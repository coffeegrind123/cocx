# cocx development targets. Unit tests need python3, node and curl (the CLI test fetches a
# Caddy binary into tests/.cache); e2e needs Docker and builds mox inside a container.
SHELL := /bin/bash
SHELLCHECK ?= shellcheck
SH_FILES := cocx lib/*.sh remote/cocx-backup hooks/provider.example mox/build.sh \
            mox/tools/*.sh tests/test_cli.sh tests/e2e/run.sh

.PHONY: test lint scrub hooks e2e e2e-caddy e2e-mox check-patches all

all: lint test scrub

test:
	node filter/test/mail-filter.test.mjs
	python3 tests/test_mail_dns.py
	python3 tests/test_bimi.py
	bash tests/test_cli.sh

lint:
	$(SHELLCHECK) -x -s bash $(SH_FILES)
	python3 -m py_compile tools/*.py remote/imap-reset.py tests/*.py
	node --check filter/mail-filter.js && node --check filter/imap-client.js && node --check filter/mime-parse.js

scrub:
	python3 tools/scrub.py

hooks:
	git config core.hooksPath .githooks

# The patch series against today's upstream main: controls + apply + frontend, no Go build.
check-patches:
	bash mox/build.sh --check

e2e: e2e-caddy e2e-mox

e2e-caddy:
	tests/e2e/run.sh caddy

e2e-mox:
	tests/e2e/run.sh mox
