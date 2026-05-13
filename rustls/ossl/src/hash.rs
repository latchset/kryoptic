use ossl::digest::{DigestAlg, OsslDigest};
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};

use crate::osslctx;

const MAX_DIGEST_SIZE: usize = 64;

pub struct OsslHash {
    alg: DigestAlg,
}

impl Hash for OsslHash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(OsslHashContext::new(self.alg))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut ctx = OsslHashContext::new(self.alg);
        ctx.update(data);
        ctx.finalize()
    }

    fn output_len(&self) -> usize {
        match self.alg {
            DigestAlg::Sha2_256 => 32,
            DigestAlg::Sha2_384 => 48,
            _ => panic!("Unexpected Digest Algorithm"),
        }
    }

    fn algorithm(&self) -> HashAlgorithm {
        match self.alg {
            DigestAlg::Sha2_256 => HashAlgorithm::SHA256,
            DigestAlg::Sha2_384 => HashAlgorithm::SHA384,
            _ => panic!("Unexpected Digest Algorithm"),
        }
    }
}

pub struct OsslHashContext {
    ctx: OsslDigest,
}

impl OsslHashContext {
    fn new(alg: DigestAlg) -> OsslHashContext {
        OsslHashContext {
            ctx: OsslDigest::new(osslctx(), alg, None)
                .expect("Failed to initialize OsslDigest"),
        }
    }

    fn finalize(&mut self) -> Output {
        let mut buf = [0u8; MAX_DIGEST_SIZE];
        let len = self.ctx.finalize(&mut buf).expect("Failed to finalize");
        Output::new(&buf[..len])
    }
}

impl Context for OsslHashContext {
    fn fork_finish(&self) -> Output {
        let mut cloned = self.ctx.clone();
        let mut buf = [0u8; MAX_DIGEST_SIZE];
        let len = cloned.finalize(&mut buf).expect("Failed to finalize");
        Output::new(&buf[..len])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(OsslHashContext {
            ctx: self.ctx.clone(),
        })
    }

    fn finish(mut self: Box<Self>) -> Output {
        self.finalize()
    }

    fn update(&mut self, data: &[u8]) {
        self.ctx.update(data).expect("Failed to update");
    }
}

pub(crate) static SHA256: OsslHash = OsslHash {
    alg: DigestAlg::Sha2_256,
};
pub(crate) static SHA384: OsslHash = OsslHash {
    alg: DigestAlg::Sha2_384,
};
