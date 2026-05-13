// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use crate::osslctx;
use ossl::mac::{MacAlg, OsslMac};
use ossl::OsslSecret;
use rustls::crypto::hmac::{Hmac, Key, Tag};

const MAX_MAC_SIZE: usize = 64;

fn hmac_to_size(alg: MacAlg) -> usize {
    // Ideally we would query the crypto library for this info,
    // but it would be very inefficient to instantiate a digest
    // object just to query the size when these sizes are well-known
    // and will never change, so we just hardcode it here for now
    match alg {
        MacAlg::HmacSha1 => 20,
        MacAlg::HmacSha2_224
        | MacAlg::HmacSha2_512_224
        | MacAlg::HmacSha3_224 => 28,
        MacAlg::HmacSha2_256
        | MacAlg::HmacSha2_512_256
        | MacAlg::HmacSha3_256 => 32,
        MacAlg::HmacSha2_384 | MacAlg::HmacSha3_384 => 48,
        MacAlg::HmacSha2_512 | MacAlg::HmacSha3_512 => 64,
        _ => panic!("Invalid HMAC algorithm"),
    }
}

pub struct OsslHmac {
    alg: MacAlg,
}

impl Hmac for OsslHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(OsslHmacKey::new(self.alg, key))
    }

    fn hash_output_len(&self) -> usize {
        hmac_to_size(self.alg)
    }
}

struct OsslHmacKey {
    alg: MacAlg,
    key: OsslSecret,
}

impl OsslHmacKey {
    fn new(alg: MacAlg, key: &[u8]) -> OsslHmacKey {
        OsslHmacKey {
            alg: alg,
            key: OsslSecret::from_slice(key),
        }
    }
}

impl Key for OsslHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = OsslMac::new(osslctx(), self.alg, self.key.make_copy())
            .expect("OsslMac::new failed");
        mac.update(first).expect("OsslMac::update failed on first");
        for m in middle {
            mac.update(m).expect("OsslMac::update failed on middle");
        }
        mac.update(last).expect("OsslMac::update failed on last");

        let mut output = [0u8; MAX_MAC_SIZE];
        let size = mac.size();
        mac.finalize(&mut output[..size])
            .expect("OsslMac::finalize failed");

        Tag::new(&output[..size])
    }

    fn tag_len(&self) -> usize {
        hmac_to_size(self.alg)
    }
}

pub const HMAC_SHA256: OsslHmac = OsslHmac {
    alg: MacAlg::HmacSha2_256,
};
pub const HMAC_SHA384: OsslHmac = OsslHmac {
    alg: MacAlg::HmacSha2_384,
};
