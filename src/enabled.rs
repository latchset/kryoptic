// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "aes")]
mod aes;

#[cfg(feature = "chacha20")]
mod chacha20;

#[cfg(feature = "ecc")]
mod ec;

#[cfg(feature = "ffdh")]
mod ffdh;
#[cfg(feature = "ffdh")]
mod ffdh_groups;

#[cfg(feature = "hash")]
mod hash;

#[cfg(feature = "hkdf")]
mod hkdf;

#[cfg(feature = "hmac")]
mod hmac;

#[cfg(feature = "ike")]
mod ike;

#[cfg(feature = "hotp")]
mod hotp;

#[cfg(feature = "pbkdf2")]
mod pbkdf2;

#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "sp800_108")]
mod sp800_108;

#[cfg(feature = "sshkdf")]
mod sshkdf;

#[cfg(feature = "tlskdf")]
mod tlskdf;

#[cfg(feature = "simplekdf")]
mod simplekdf;

#[cfg(feature = "mlkem")]
mod mlkem;

// Excluded under awslc-fips specifically (not plain awslc): AWS-LC does
// implement ML-DSA sign/verify, but its presence inside AWS-LC-FIPS's
// validated boundary is not publicly confirmed as of this writing (only
// ML-KEM is documented as validated in the AWS-LC-FIPS 3.0 module), so
// this backend declines to advertise/perform ML-DSA operations under a
// FIPS-mode build until that changes, rather than claim an approval
// status kryoptic cannot vouch for. Plain awslc has no such restriction.
#[cfg(all(feature = "mldsa", not(feature = "awslc-fips")))]
mod mldsa;

// In fips builds enable slhdsa only if ossl400 was selected, which is required
// for deferred self tests. Never for awslc/awslc-fips: AWS-LC has no SLH-DSA/
// SPHINCS+ primitive at all (confirmed against aws-lc-sys's public headers --
// no matching symbols anywhere, for either backend variant), so this is
// excluded outright rather than relying on the ossl400 check above, which is
// an OpenSSL-FIPS-module-specific requirement that says nothing about this
// backend (and, unlike awslc-fips, plain awslc doesn't imply `fips` at all,
// so that check alone doesn't protect it).
#[cfg(all(
    feature = "slhdsa",
    not(any(feature = "awslc", feature = "awslc-fips")),
    any(not(feature = "fips"), feature = "ossl400")
))]
mod slhdsa;

use mechanism::Mechanisms;
use object::ObjectFactories;

/// Registers all mechanisms and object factories that have been enabled
/// at compile time. Called by [Token::new]
fn register_all(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    object::factory::register(mechs, ot);

    #[cfg(feature = "aes")]
    aes::register(mechs, ot);

    #[cfg(feature = "chacha20")]
    chacha20::register(mechs, ot);

    #[cfg(feature = "ecdsa")]
    ec::ecdsa::register(mechs, ot);

    #[cfg(feature = "ecdh")]
    ec::ecdh::register(mechs, ot);

    #[cfg(feature = "ec_montgomery")]
    ec::montgomery::register(mechs, ot);

    #[cfg(feature = "eddsa")]
    ec::eddsa::register(mechs, ot);

    #[cfg(feature = "ffdh")]
    ffdh::register(mechs, ot);

    #[cfg(feature = "hash")]
    hash::register(mechs, ot);

    #[cfg(feature = "hkdf")]
    hkdf::register(mechs, ot);

    #[cfg(feature = "hmac")]
    hmac::register(mechs, ot);

    #[cfg(feature = "ike")]
    ike::register(mechs, ot);

    #[cfg(feature = "hotp")]
    hotp::register(mechs, ot);

    #[cfg(feature = "pbkdf2")]
    pbkdf2::register(mechs, ot);

    #[cfg(feature = "rsa")]
    rsa::register(mechs, ot);

    #[cfg(feature = "sp800_108")]
    sp800_108::register(mechs, ot);

    #[cfg(feature = "sshkdf")]
    sshkdf::register(mechs, ot);

    #[cfg(feature = "tlskdf")]
    tlskdf::register(mechs, ot);

    #[cfg(feature = "simplekdf")]
    simplekdf::register(mechs, ot);

    #[cfg(feature = "mlkem")]
    mlkem::register(mechs, ot);

    // See the `not(feature = "awslc-fips")` mod-inclusion gate above for
    // why this is excluded specifically under awslc-fips.
    #[cfg(all(feature = "mldsa", not(feature = "awslc-fips")))]
    mldsa::register(mechs, ot);

    #[cfg(all(
        feature = "slhdsa",
        not(any(feature = "awslc", feature = "awslc-fips")),
        any(not(feature = "fips"), feature = "ossl400")
    ))]
    slhdsa::register(mechs, ot);

    #[cfg(feature = "fips")]
    fips::register(mechs, ot);
}
