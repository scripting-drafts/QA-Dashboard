PYTHON ?= python3
SENTINELS := sentinels

.PHONY: deps test test-sentinels test-dashboard contracts contracts-check \
	vendor-check build-linux build-windows build-macos build-logs release-check \
	start install uninstall clean

deps:
	npm ci --no-audit --no-fund

test: test-dashboard test-sentinels contracts-check vendor-check

test-dashboard:
	npm test

test-sentinels:
	cd $(SENTINELS) && $(PYTHON) -m unittest discover -s tests

contracts:
	$(PYTHON) tools/export_contracts.py

contracts-check:
	$(PYTHON) tools/export_contracts.py --check

vendor-check:
	$(PYTHON) tools/check_vendor.py

build-linux:
	npm run pack:linux

build-windows:
	npm run pack:win

build-macos:
	npm run pack:mac

build-logs:
	npm run pack:logs

release-check:
	cd $(SENTINELS) && ./bin/qa legal --check
	$(PYTHON) tools/check_vendor.py
	npm test

start:
	npm start

install:
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -rf dist dist-logs
