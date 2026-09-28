// X25519, wrapping AWS-LC's dedicated raw X25519_* functions.

use crate::error::{Error, ErrorKind};
use crate::ffi;

/// X25519's private key IS the raw 32-byte scalar PKCS#11 stores directly
/// for CKK_EC_MONTGOMERY (CKA_VALUE) -- unlike Ed25519 there's no
/// seed-vs-expanded-key distinction to track.
pub struct X25519Key {
    private: [u8; 32],
    public: [u8; 32],
}

// A plain `#[derive(Debug)]` would print `private` -- the raw private
// key material -- in cleartext on any `{:?}` format of this type. Only
// the public key is safe to show.
redacting_debug!(X25519Key {
    redact: [private],
    show: [public],
});

impl X25519Key {
    pub fn generate() -> Result<X25519Key, Error> {
        let mut public = [0u8; 32];
        let mut private = [0u8; 32];
        unsafe {
            ffi::X25519_keypair(public.as_mut_ptr(), private.as_mut_ptr());
        }
        Ok(X25519Key { private, public })
    }

    /// Reconstructs a key from a raw 32-byte private scalar (PKCS#11's
    /// CKA_VALUE format for CKK_EC_MONTGOMERY X25519).
    pub fn from_private(priv_key: &[u8; 32]) -> Result<X25519Key, Error> {
        let mut public = [0u8; 32];
        // Confirmed against the vendored aws-lc-sys bindings
        // (x86_64_unknown_linux_gnu_crypto.rs): X25519_public_from_private
        // exists under that exact name, returns void, parameter order
        // (out_public_value, private_key) -- matches the plan's sketch.
        unsafe {
            ffi::X25519_public_from_private(
                public.as_mut_ptr(),
                priv_key.as_ptr(),
            );
        }
        Ok(X25519Key {
            private: *priv_key,
            public,
        })
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.private
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn derive_shared_secret(
        &self,
        peer_public: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let mut secret = [0u8; 32];
        let ret = unsafe {
            ffi::X25519(
                secret.as_mut_ptr(),
                self.private.as_ptr(),
                peer_public.as_ptr(),
            )
        };
        if ret != 1 {
            // X25519 returns 0 for a small-order/all-zero shared secret
            // (a known attack input) -- this is a real, expected rejection
            // case, not just a generic backend failure. AgreementFailed
            // (not VerifyFailed): this is a key-agreement failure, not a
            // signature/tag check, and maps to a different CK_RV (see
            // crate::error's From<crate::lowlevel::Error> impl) since
            // CKR_SIGNATURE_INVALID is not a valid C_DeriveKey return code.
            return Err(Error::new(ErrorKind::AgreementFailed));
        }
        Ok(secret)
    }
}

impl Drop for X25519Key {
    fn drop(&mut self) {
        for byte in self.private.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// No `unsafe impl Send/Sync` here: X25519Key holds only fixed-size byte
// arrays (no raw pointers, no interior mutability), so it's already
// auto-Send + auto-Sync -- the equivalent impls on the similarly-shaped
// Ed25519Key were removed as redundant for the same reason.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_agreement() {
        let key1 = X25519Key::generate().unwrap();
        let key2 = X25519Key::generate().unwrap();
        let secret1 = key1.derive_shared_secret(&key2.public_key()).unwrap();
        let secret2 = key2.derive_shared_secret(&key1.public_key()).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn from_private_reproduces_same_public_key() {
        let key1 = X25519Key::generate().unwrap();
        let key2 = X25519Key::from_private(&key1.private_key()).unwrap();
        assert_eq!(key1.public_key(), key2.public_key());
    }

    /// The hand-written `Debug` impl must never print the raw private
    /// scalar in cleartext, only a redaction placeholder -- mirrors
    /// `awslc::eddsa::Ed25519Key`'s own equivalent test, added after
    /// review found that type's derived `Debug` leaking private key
    /// material.
    #[test]
    fn debug_format_redacts_private_key_material() {
        let key = X25519Key::generate().unwrap();
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains(&format!("{:?}", key.private)));
        assert!(debug_str.contains("REDACTED"));
        // The public key is not secret and is fine to show.
        assert!(debug_str.contains(&format!("{:?}", key.public)));
    }
}
