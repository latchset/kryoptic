// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(all(feature = "dynamic", feature = "fips"))]
compile_error!("Feature 'dynamic' and 'fips' are mutually exclusive and cannot be enabled together");

#[cfg(all(
    feature = "ecdh",
    not(any(feature = "ecdsa", feature = "ec_montgomery"))
))]
compile_error!("Feature 'ecdh' requires either 'ecdsa' or 'ec_montgomery'");

#[cfg(feature = "aes")]
mod aes;

#[cfg(feature = "ecc")]
mod ec;

#[cfg(feature = "hash")]
mod hash;

#[cfg(feature = "hkdf")]
mod hkdf;

#[cfg(feature = "hmac")]
mod hmac;

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

use mechanism::Mechanisms;
use object::ObjectFactories;

pub fn register_all(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    object::register(mechs, ot);

    #[cfg(feature = "aes")]
    aes::register(mechs, ot);

    #[cfg(feature = "ecdsa")]
    ec::ecdsa::register(mechs, ot);

    #[cfg(feature = "ecdh")]
    ec::ecdh::register(mechs, ot);

    #[cfg(feature = "ec_montgomery")]
    ec::montgomery::register(mechs, ot);

    #[cfg(feature = "eddsa")]
    ec::eddsa::register(mechs, ot);

    #[cfg(feature = "hash")]
    hash::register(mechs, ot);

    #[cfg(feature = "hkdf")]
    hkdf::register(mechs, ot);

    #[cfg(feature = "hmac")]
    hmac::register(mechs, ot);

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

    #[cfg(feature = "fips")]
    fips::register(mechs, ot);
}
