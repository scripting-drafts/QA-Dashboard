.PHONY: test install uninstall

test:
	python3 -m compileall -q qadesk tests
	python3 -m unittest discover -s tests -v

install:
	./install.sh

uninstall:
	./uninstall.sh
