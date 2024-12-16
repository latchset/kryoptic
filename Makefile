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
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' ! -name 'bindings.rs' | xargs rustfmt --check --color auto

fix-format:
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' ! -name 'bindings.rs' | xargs rustfmt

check-spell:
	@.github/codespell.sh

tests: build
	src/tools/softhsm/test.sh

docs:
	cargo doc --features standard,nssdb,jsondb,fips --document-private-items
