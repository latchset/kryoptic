all: build

build:
	cargo build --features nssdb

fips:
	cargo build --no-default-features --features fips,sqlitedb,nssdb

static:
	cargo build --no-default-features --features standard

check:
	cargo test --features nssdb

check-fips:
	cargo test --no-default-features --features fips,sqlitedb,nssdb

check-static:
	cargo test --no-default-features --features standard

check-format:
	@find ./src build.rs -name '*.rs' | xargs rustfmt --check --color auto

fix-format:
	@find ./src build.rs -name '*.rs' | xargs rustfmt

check-spell:
	@.github/codespell.sh

tests: build
	src/tools/softhsm/test.sh

docs:
	cargo doc --no-default-features --features nssdb,jsondb,fips --document-private-items

.ONESHELL:
SHELL = /bin/bash
scope:
	@if [ -x "$$(command -v scope)" ]; then
		PKCSFILES=$$(find ./ -name pkcs11_bindings.rs)
		if [[ -n "$$PKCSFILES" ]]; then
			read PKCSFILE < <(ls -t $$PKCSFILES)
		fi
		OSSLFILES=$$(find ./ -name ossl_bindings.rs)
		if [[ -n "$$OSSLFILES" ]]; then
			read OSSLFILE < <(ls -t $$OSSLFILES)
		fi
		scope -- src $$PKCSFILE $$OSSLFILE
	fi

tags: scope
	ctags -R src/

clean:
	cargo clean
