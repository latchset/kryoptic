use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::derive::EcdhDerive;
use ossl::pkey::{EvpPkey, EvpPkeyType, PkeyData};

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use crate::osslctx;

/* whis will need to grop up to 1024 bytes if we ever add support for FFDH groups
 * (we most likely never will) */
const MAX_SHARED_SECRET_SIZE: usize = 128;

#[derive(Debug)]
pub struct OsslEcKxGroup(pub NamedGroup);

impl SupportedKxGroup for OsslEcKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key_type = match self.0 {
            NamedGroup::X25519 => EvpPkeyType::X25519,
            NamedGroup::secp256r1 => EvpPkeyType::P256,
            NamedGroup::secp384r1 => EvpPkeyType::P384,
            NamedGroup::secp521r1 => EvpPkeyType::P521,
            _ => return Err(Error::General("Unsupported KX group".into())),
        };

        let privkey = EvpPkey::generate(osslctx(), key_type)
            .map_err(|_| Error::General("Failed to generate KX key".into()))?;

        let pubkey = match privkey.export_public() {
            Ok(PkeyData::Ecc(ecc)) => {
                if let Some(k) = &ecc.pubkey {
                    Some(k.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
        .ok_or_else(|| Error::General("Failed to get KX public key".into()))?;

        Ok(Box::new(OsslEcdh {
            group: self.0,
            privkey,
            pubkey,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }

    fn fips(&self) -> bool {
        match self.0 {
            NamedGroup::X25519 => {
                EvpPkey::available(osslctx(), EvpPkeyType::X25519)
            }
            NamedGroup::secp256r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P256)
            }
            NamedGroup::secp384r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P384)
            }
            NamedGroup::secp521r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P521)
            }
            _ => false,
        }
    }
}

pub struct OsslEcdh {
    group: NamedGroup,
    privkey: EvpPkey,
    pubkey: Vec<u8>,
}

impl ActiveKeyExchange for OsslEcdh {
    fn complete(
        mut self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, Error> {
        match self.group {
            NamedGroup::X25519 => {
                if peer.len() != 32 {
                    return Err(Error::PeerMisbehaved(
                        PeerMisbehaved::InvalidKeyShare,
                    ));
                }
            }
            NamedGroup::secp256r1
            | NamedGroup::secp384r1
            | NamedGroup::secp521r1 => {
                if peer.first() != Some(&0x04) {
                    return Err(Error::PeerMisbehaved(
                        PeerMisbehaved::InvalidKeyShare,
                    ));
                }
            }
            _ => {
                return Err(Error::PeerMisbehaved(
                    PeerMisbehaved::InvalidKeyShare,
                ))
            }
        };
        let mut peer_key =
            self.privkey.make_peer(osslctx(), peer).map_err(|_| {
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
            })?;

        let mut derive = EcdhDerive::new(osslctx(), &mut self.privkey)
            .map_err(|_| {
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
            })?;

        let mut secret = [0u8; MAX_SHARED_SECRET_SIZE];
        let len = derive.derive(&mut peer_key, &mut secret).map_err(|_| {
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        })?;

        Ok(SharedSecret::from(&secret[..len]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

#[derive(Debug)]
pub struct OsslKemKxGroup(pub NamedGroup);

impl SupportedKxGroup for OsslKemKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key_type = match self.0 {
            NamedGroup::MLKEM768 => EvpPkeyType::MlKem768,
            NamedGroup::MLKEM1024 => EvpPkeyType::MlKem1024,
            _ => return Err(Error::General("Unsupported KX group".into())),
        };

        let privkey = EvpPkey::generate(osslctx(), key_type)
            .map_err(|_| Error::General("Failed to generate KX key".into()))?;

        let pubkey = match privkey.export_public() {
            Ok(PkeyData::Mlkey(mlkem)) => {
                if let Some(k) = &mlkem.pubkey {
                    Some(k.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
        .ok_or_else(|| Error::General("Failed to get KX public key".into()))?;

        Ok(Box::new(OsslKem {
            group: self.0,
            privkey,
            pubkey,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

pub struct OsslKem {
    group: NamedGroup,
    privkey: EvpPkey,
    pubkey: Vec<u8>,
}

impl ActiveKeyExchange for OsslKem {
    fn complete(
        mut self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, Error> {
        let mut cipher = OsslAsymcipher::new(
            osslctx(),
            EncOp::Decapsulate,
            &mut self.privkey,
            None,
        )
        .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        let secret = cipher.decapsulate(peer).map_err(|_| {
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        })?;

        Ok(SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

pub static X25519: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::X25519);

pub static SECP256R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp256r1);

pub static SECP384R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp384r1);

pub static SECP521R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp521r1);

pub static MLKEM768: OsslKemKxGroup = OsslKemKxGroup(NamedGroup::MLKEM768);

pub static MLKEM1024: OsslKemKxGroup = OsslKemKxGroup(NamedGroup::MLKEM1024);

static SUPPORTED_KX_GROUPS: std::sync::OnceLock<
    Vec<&'static dyn SupportedKxGroup>,
> = std::sync::OnceLock::new();

pub fn supported_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    let groups = SUPPORTED_KX_GROUPS.get_or_init(|| {
        let mut v: Vec<&'static dyn SupportedKxGroup> = Vec::with_capacity(5);

        if EvpPkey::available(osslctx(), EvpPkeyType::MlKem1024) {
            v.push(&MLKEM1024);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::MlKem768) {
            v.push(&MLKEM768);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::X25519) {
            v.push(&X25519);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P521) {
            v.push(&SECP521R1);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P384) {
            v.push(&SECP384R1);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P256) {
            v.push(&SECP256R1);
        }

        v
    });
    groups.clone()
}
