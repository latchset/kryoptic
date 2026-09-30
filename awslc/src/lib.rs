//! Safe Rust wrappers around AWS-LC, providing the primitives kryoptic's
//! `src/awslc/*` module tree needs to implement kryoptic's
//! backend-agnostic `Mechanism` traits.
//!
//! Built against exactly one of two low-level FFI crates, selected by
//! this crate's own `non-fips`/`fips` Cargo features (mutually
//! exclusive -- see the `compile_error!`s below): `aws-lc-sys` (plain
//! AWS-LC) or `aws-lc-fips-sys` (AWS-LC's FIPS-140-3-validated module).
//! Every module below is written once against the `ffi` alias defined
//! here and compiles unchanged against either backend.

#[cfg(all(feature = "non-fips", feature = "fips"))]
compile_error!("features `non-fips` and `fips` are mutually exclusive");
#[cfg(not(any(feature = "non-fips", feature = "fips")))]
compile_error!("exactly one of `non-fips` or `fips` must be enabled");

#[cfg(feature = "fips")]
use aws_lc_fips_sys as ffi;
#[cfg(feature = "non-fips")]
use aws_lc_sys as ffi;

pub mod error;
pub use error::{Error, ErrorKind};
#[macro_use]
pub mod cipher;
pub mod dh;
pub mod digest;
pub mod ec;
pub mod eddsa;
pub mod hkdf;
pub mod kbkdf;
pub mod mac;
pub mod mldsa;
pub mod mlkem;
pub mod pbkdf2;
pub mod rand;
pub mod rsa;
pub mod sshkdf;
pub mod x25519;
