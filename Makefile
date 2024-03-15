all:
	cargo build

fips:
	cargo build --features fips

check:
	cargo test

check-fips:
	cargo test --features fips

check-format:
	@rustfmt --check --color auto src/*.rs src/*/*.rs

fix-format:
	@rustfmt src/*.rs src/*/*.rs

check-spell:
	codespell --ignore-words-list="sorce,clen,adin,ciph,tolen,ot,siz" src
