all: build

build:
	cargo build --features standard,nssdb

fips:
	cargo build --features fips

check:
	cargo test --features standard,nssdb

check-fips:
	cargo test --features fips

check-format:
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' | xargs rustfmt --check --color auto

fix-format:
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' | xargs rustfmt

check-spell:
	@.github/codespell.sh

tests: build
	src/tools/softhsm/test.sh

docs:
	cargo doc --features standard,nssdb,jsondb,fips --document-private-items

.ONESHELL:
SHELL = /bin/bash
scope:
	@if [ -x "$$(command -v scope)" ]; then
		PKCSFILES=$$(find ./ -name pkcs11_bindings.rs)
		if [[ -n "$$PKCSFILES" ]]; then
			read PKCSFILE < <(ls -t $$PKCSFILES)
		fi
		OSSLFILES=$$(find ./ -name pkcs11_bindings.rs)
		if [[ -n "$$OSSLFILES" ]]; then
			read OSSLFILE < <(ls -t $$OSSLFILES)
		fi
		scope -- src $$PKCSFILE $$OSSLFILE
	fi

tags: scope
	ctags -R src/

clean:
	cargo clean
