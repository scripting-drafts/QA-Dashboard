PYTHON ?= python3
SENTINELS := sentinels

.PHONY: deps test test-sentinels test-dashboard contracts contracts-check \
	build-linux build-windows build-macos build-logs release-check \
	start install uninstall clean

deps:
	npm ci --no-audit --no-fund

test: test-dashboard test-sentinels contracts-check

test-dashboard:
	npm test

test-sentinels:
	cd $(SENTINELS) && $(PYTHON) -m unittest discover -s tests

contracts:
	$(PYTHON) tools/export_contracts.py

contracts-check:
	$(PYTHON) tools/export_contracts.py --check

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
	npm test

start:
	npm start

install:
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -rf dist dist-logs
