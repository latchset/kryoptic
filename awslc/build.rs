// Copyright 2026
// See LICENSE.txt file for terms
//
// Compiles `csrc/sshkdf_shim.c`, which reaches AWS-LC's SSHKDF()
// directly since neither aws-lc-sys nor aws-lc-fips-sys ever exposes it
// (see that file for why). Whichever of the two is active (this
// crate's own mutually exclusive `non-fips`/`fips` features) sets a
// `DEP_AWS_LC_<major>_<minor>_<patch>_INCLUDE` (`non-fips`) or
// `DEP_AWS_LC_FIPS_<major>_<minor>_<patch>_INCLUDE` (`fips`) env var
// (Cargo's standard `DEP_<LINKS>_<KEY>` convention, where `links`
// deliberately bakes in the exact version -- see each crate's own
// Cargo.toml). Neither of `awslc`'s two direct dependencies is pinned
// to an exact patch here (aws-lc-sys allows any 0.34.x; aws-lc-fips-sys
// is exactly pinned in this crate's own Cargo.toml, but that pin is
// still a single version whose exact env var name shouldn't be
// hardcoded twice), so scanning for the prefix pattern instead of the
// full var name keeps this working without an edit here across patch
// bumps.

fn main() {
    println!("cargo:rerun-if-changed=csrc/sshkdf_shim.c");
    let include = find_include_path();
    cc::Build::new()
        .file("csrc/sshkdf_shim.c")
        .include(include)
        .compile("kryoptic_awslc_sshkdf_shim");
}

fn find_include_path() -> String {
    // `DEP_AWS_LC_FIPS_...` also starts with `DEP_AWS_LC_`, but this
    // crate's own `non-fips`/`fips` features are mutually exclusive (see
    // src/lib.rs's compile_error! guards), so only one of aws-lc-sys/
    // aws-lc-fips-sys is ever an active dependency in a given build --
    // at most one `DEP_AWS_LC*_INCLUDE`-shaped var can exist regardless
    // of which prefix is scanned for.
    #[cfg(feature = "fips")]
    let prefix = "DEP_AWS_LC_FIPS_";
    #[cfg(not(feature = "fips"))]
    let prefix = "DEP_AWS_LC_";

    for (key, value) in std::env::vars() {
        if key.starts_with(prefix) && key.ends_with("_INCLUDE") {
            return value;
        }
    }
    panic!(
        "no {prefix}*_INCLUDE env var found: the active aws-lc-sys/\
         aws-lc-fips-sys did not export its include path, or renamed its \
         `links` key in a way this pattern no longer matches"
    );
}
