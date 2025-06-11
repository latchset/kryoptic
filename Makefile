TESTS:=

all: build

build:
	cargo build --features nssdb

fips:
	cargo build --no-default-features --features fips,nssdb

static:
	cargo build --no-default-features --features standard

check:
	cargo test --features nssdb,log $(TESTS)

check-fips:
	cargo test --no-default-features --features fips,nssdb,log $(TESTS)

check-static:
	cargo test --no-default-features --features standard,log $(TESTS)

check-format:
	@find ./cdylib -name '*.rs' | xargs rustfmt --check --color auto
	@find ./ossl -name '*.rs' | xargs rustfmt --check --color auto --edition 2021
	@find ./pkcs11 -name '*.rs' | xargs rustfmt --check --color auto
	@find ./src -name '*.rs' | xargs rustfmt --check --color auto --edition 2021
	@find ./tools -name '*.rs' | xargs rustfmt --check --color auto

fix-format:
	@find ./cdylib -name '*.rs' | xargs rustfmt
	@find ./ossl -name '*.rs' | xargs rustfmt --edition 2021
	@find ./pkcs11 -name '*.rs' | xargs rustfmt
	@find ./src -name '*.rs' | xargs rustfmt --edition 2021
	@find ./tools -name '*.rs' | xargs rustfmt

check-spell:
	@.github/codespell.sh

tests: build
	src/tools/softhsm/test.sh

docs:
	cargo doc --no-default-features --features standard,pqc,nssdb,log --document-private-items

docs-fips:
	cargo doc --no-default-features --features fips --document-private-items

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
		scope -- cdylib ossl pkcs11 src tools $$PKCSFILE $$OSSLFILE
	fi

tags: scope
	ctags -R src/

clean:
	cargo clean
