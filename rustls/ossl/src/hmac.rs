// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use crate::osslctx;
use ossl::mac::{MacAlg, OsslMac};
use ossl::OsslSecret;
use rustls::crypto::hmac::{Hmac, Key, Tag};

const MAX_MAC_SIZE: usize = 64;

pub struct OsslHmac {
    alg: MacAlg,
    outlen: usize,
}

impl OsslHmac {
    pub const fn new(alg: MacAlg, outlen: usize) -> Self {
        Self { alg, outlen }
    }
}

impl Hmac for OsslHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(OsslHmacKey::new(self.alg, key))
    }

    fn hash_output_len(&self) -> usize {
        self.outlen
    }
}

struct OsslHmacKey {
    mac: OsslMac,
}

impl OsslHmacKey {
    fn new(alg: MacAlg, key: &[u8]) -> OsslHmacKey {
        OsslHmacKey {
            mac: OsslMac::new(osslctx(), alg, OsslSecret::from_slice(key))
                .expect("OsslMac::new failed"),
        }
    }
}

impl Key for OsslHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = self.mac.clone();
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
        self.mac.size()
    }
}

pub const HMAC_SHA256: OsslHmac = OsslHmac::new(MacAlg::HmacSha2_256, 32);
pub const HMAC_SHA384: OsslHmac = OsslHmac::new(MacAlg::HmacSha2_384, 48);
