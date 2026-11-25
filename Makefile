PYTHON ?= python3
RELEASE_BOARD ?= release-board
SENTINELS := sentinels
SENTINELS_HOME := $(CURDIR)/$(SENTINELS)

.PHONY: deps test test-dashboard test-tools test-sentinels contracts \
	contracts-check vendor-check vendor-sync rules-html rules-check \
	build-linux build-windows build-macos build-logs release-check \
	release-tag-check release-tag-fix hooks start install uninstall clean

deps:
	npm ci --no-audit --no-fund

test: test-dashboard test-tools test-sentinels contracts-check vendor-check rules-check

test-dashboard:
	npm test

test-tools:
	$(PYTHON) -m unittest discover -s tools/tests

test-sentinels:
	cd $(SENTINELS) && QA_SENTINELS_HOME=$(SENTINELS_HOME) $(PYTHON) -m unittest discover -s tests

contracts:
	$(PYTHON) tools/export_contracts.py

contracts-check:
	$(PYTHON) tools/export_contracts.py --check

vendor-check:
	$(PYTHON) tools/check_vendor.py

vendor-sync:
	$(PYTHON) tools/sync_vendor.py --write --ref "$(REF)" \
		--require-signature --generate

rules-html:
	$(PYTHON) tools/build_rules_html.py

rules-check:
	$(PYTHON) tools/build_rules_html.py --check

build-linux:
	npm run pack:linux

build-windows:
	npm run pack:win

build-macos:
	npm run pack:mac

build-logs:
	npm run pack:logs

release-tag-check:
	$(PYTHON) tools/check_release_tag.py

release-tag-fix:
	$(RELEASE_BOARD) repair --root . --bump --move-tag --commit --confirm

hooks:
	./scripts/install-hooks.sh

release-check: release-tag-check
	cd $(SENTINELS) && QA_SENTINELS_HOME=$(SENTINELS_HOME) ./bin/qa legal --check
	$(PYTHON) tools/check_vendor.py
	$(PYTHON) tools/build_rules_html.py --check
	npm test

start:
	npm start

install:
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -rf dist dist-logs
