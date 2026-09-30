// AES-GCM, wrapping AWS-LC's one-shot `EVP_AEAD` API.

use crate::error::{Error, ErrorKind};
use crate::ffi;

/// Implements `Debug` for a struct that holds secret key material,
/// printing the fields named in `redact` as `"[REDACTED]"` and every
/// other named field verbatim. Removes the boilerplate every hand-written
/// redacting `Debug` impl in this backend would otherwise duplicate (see
/// e.g. `AesKeyWrap`/`AesCcm` below, `X25519Key`, `Ed25519Key`) -- and,
/// unlike a plain `#[derive(Debug)]`, forces whoever adds a new field to
/// one of these structs to explicitly list it in `redact` or `show`
/// rather than silently inheriting a leak (this is exactly how the
/// `AesOperation`/`AesKeyWrap` cleartext-key-in-Debug bug happened: a
/// derive that never asked the question). The optional `show_fips` group
/// exists for kryoptic-lib's own callers (e.g. `AesOperation` in
/// `src/awslc/aes.rs`), whose struct has a real `#[cfg(feature =
/// "fips")]`-gated field; it's simply unused (and therefore inert) in
/// this crate, which has no `fips` feature of its own.
#[macro_export]
macro_rules! redacting_debug {
    (
        $ty:ident {
            redact: [$($redact:ident),* $(,)?],
            show: [$($show:ident),* $(,)?]
            $(, show_fips: [$($show_fips:ident),* $(,)?])? $(,)?
        }
    ) => {
        impl std::fmt::Debug for $ty {
            fn fmt(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                #[allow(unused_mut)]
                let mut d = f.debug_struct(stringify!($ty));
                $( d.field(stringify!($redact), &"[REDACTED]"); )*
                $( d.field(stringify!($show), &self.$show); )*
                $($(
                    #[cfg(feature = "fips")]
                    d.field(stringify!($show_fips), &self.$show_fips);
                )*)?
                d.finish()
            }
        }
    };
}

/// A one-shot AEAD primitive: `AesGcm` and `AesCcm` below already share
/// this exact `seal`/`open` shape (both take `(nonce, aad, plaintext/
/// ciphertext, out)` and return the bytes written, or `(nonce, aad,
/// ciphertext, tag, out)` and return the plaintext length), so this
/// trait formalizes that parity rather than leaving it as an unstated
/// convention two independent impl blocks happen to follow. `src/awslc/
/// aes.rs`'s message-mode `Final` dispatch (`msg_encrypt_final`/
/// `msg_decrypt_final`) uses it to collapse its `match self.mech {
/// CKM_AES_GCM => ..., CKM_AES_CCM => ... }` construction step down to a
/// single call site instead of two copies of the same `seal`/`open` call.
pub trait OneShotAead {
    /// Encrypts `plaintext` into `out` (at least `plaintext.len() +
    /// tag_len` bytes), returning the number of bytes written
    /// (ciphertext followed by the tag).
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error>;

    /// Decrypts `ciphertext`/`tag` (kept separate, per kryoptic's
    /// `CK_GCM_MESSAGE_PARAMS`/`CK_CCM_MESSAGE_PARAMS` convention) into
    /// `out`, returning the plaintext length, or an error if the tag
    /// doesn't verify.
    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error>;
}

/// Zeroes `buf` in a way the compiler won't optimize away. Mirrors
/// kryoptic-lib's `crate::misc::zeromem` (this crate has no dependency on
/// kryoptic-lib, so it needs its own copy).
pub(crate) fn zeromem(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// An owned byte buffer that scrubs its contents on drop, on every exit
/// path -- success, error, or panic -- rather than relying on whoever
/// holds it to remember a manual `zeromem()` call before every early
/// return. That manual-scrub-on-every-path pattern is exactly where two
/// real bugs in this backend came from (a forgotten `zeromem()` on one
/// specific `unwrap_cipher` error path, and the same class of issue in
/// RSA's raw-transform buffers): a `SecretBuf` makes the bug structurally
/// impossible instead of reviewer-dependent, the same way `OsslSecret`
/// does for the OpenSSL backend. Deliberately does not derive `Clone`
/// (mirrors `OsslSecret`'s own doc comment: prevents accidental copies of
/// the secret content) and hand-writes `Debug` rather than deriving it
/// (a derived impl would print the raw bytes).
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    /// A new, zero-filled buffer of exactly `len` bytes.
    pub fn zeroed(len: usize) -> SecretBuf {
        SecretBuf(vec![0u8; len])
    }

    /// Takes ownership of an existing `Vec<u8>` without copying it.
    pub fn from_vec(data: Vec<u8>) -> SecretBuf {
        SecretBuf(data)
    }

    /// Moves the bytes out as a plain `Vec<u8>`, without scrubbing them
    /// (the caller is taking over ownership/responsibility for the data,
    /// e.g. to return it as the operation's actual output) -- leaves this
    /// `SecretBuf` empty, so its own `Drop` becomes a no-op.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    /// Shrinks to `len` bytes, scrubbing the discarded tail first (unlike
    /// `Vec::truncate`, which just drops the excess elements without
    /// zeroing the memory they occupied).
    pub fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            zeromem(&mut self.0[len..]);
        }
        self.0.truncate(len);
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        zeromem(&mut self.0);
    }
}

impl std::ops::Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretBuf").field(&"[REDACTED]").finish()
    }
}

#[cfg(test)]
mod secret_buf_tests {
    use super::SecretBuf;

    #[test]
    fn zeroed_has_requested_length_and_is_all_zero() {
        let buf = SecretBuf::zeroed(16);
        assert_eq!(buf.len(), 16);
        assert_eq!(&buf[..], &[0u8; 16][..]);
    }

    #[test]
    fn deref_allows_normal_slice_use() {
        let mut buf = SecretBuf::zeroed(4);
        buf.copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&buf[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn into_vec_preserves_content() {
        let mut buf = SecretBuf::zeroed(4);
        buf.copy_from_slice(&[9, 8, 7, 6]);
        assert_eq!(buf.into_vec(), vec![9, 8, 7, 6]);
    }

    #[test]
    fn truncate_shrinks_and_scrubs_discarded_tail() {
        // The discarded tail's scrub isn't independently observable from
        // outside `SecretBuf` (same reasoning `drop_scrubs_key_material`-
        // style tests elsewhere in this backend document: reading memory
        // back after drop/truncate isn't a reliable way to observe a
        // scrub, since allocators reuse freed/shrunk blocks). This test
        // pins down the length/content contract only.
        let mut buf = SecretBuf::zeroed(8);
        buf.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        buf.truncate(4);
        assert_eq!(&buf[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn debug_format_redacts_content() {
        let mut buf = SecretBuf::zeroed(4);
        buf.copy_from_slice(&[0xAA; 4]);
        let debug_str = format!("{:?}", buf);
        assert!(!debug_str.contains("170")); // 0xAA == 170 decimal
        assert!(debug_str.contains("REDACTED"));
    }
}

#[derive(Debug)]
pub struct AesGcm {
    ctx: *mut ffi::EVP_AEAD_CTX,
    tag_len: usize,
}

impl AesGcm {
    /// `key` must be 16, 24 or 32 bytes (AES-128, AES-192 or AES-256).
    /// `tag_len` is the truncated GCM tag length in bytes (kryoptic's
    /// internal usage uses 8; the PKCS#11 CKM_AES_GCM mechanism can request
    /// others).
    pub fn new(key: &[u8], tag_len: usize) -> Result<AesGcm, Error> {
        let aead = match key.len() {
            16 => unsafe { ffi::EVP_aead_aes_128_gcm() },
            24 => unsafe { ffi::EVP_aead_aes_192_gcm() },
            32 => unsafe { ffi::EVP_aead_aes_256_gcm() },
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        };
        if aead.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ctx = unsafe {
            ffi::EVP_AEAD_CTX_new(aead, key.as_ptr(), key.len(), tag_len)
        };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(AesGcm { ctx, tag_len })
    }

    /// Encrypts `plaintext` into `out` (which must be at least
    /// `plaintext.len() + tag_len` bytes) and returns the number of bytes
    /// written: ciphertext followed by the tag (matching AWS-LC's
    /// concatenated `seal` output — callers that need the tag separate,
    /// like kryoptic's `CK_GCM_MESSAGE_PARAMS` handling, split
    /// `out[..plaintext.len()]` / `out[plaintext.len()..]` themselves).
    pub fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if out.len() < plaintext.len() + self.tag_len {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut out_len: usize = 0;
        let ret = unsafe {
            ffi::EVP_AEAD_CTX_seal(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(out_len)
    }

    /// Decrypts `ciphertext`/`tag` (kept separate, per kryoptic's
    /// `CK_GCM_MESSAGE_PARAMS` convention) into `out`. Returns the
    /// plaintext length, or an error if the tag doesn't verify.
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if out.len() < ciphertext.len() {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);

        let mut out_len: usize = 0;
        let ret = unsafe {
            ffi::EVP_AEAD_CTX_open(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                combined.as_ptr(),
                combined.len(),
                aad.as_ptr(),
                aad.len(),
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(out_len)
    }
}

impl OneShotAead for AesGcm {
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        AesGcm::seal(self, nonce, aad, plaintext, out)
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        AesGcm::open(self, nonce, aad, ciphertext, tag, out)
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        unsafe { ffi::EVP_AEAD_CTX_free(self.ctx) };
    }
}

// SAFETY: `AesGcm` exclusively owns its `*mut EVP_AEAD_CTX`, so Send is
// sound. For Sync: AWS-LC's `include/openssl/aead.h` states "This
// function may be called concurrently with itself or any other seal/open
// function on the same |EVP_AEAD_CTX|" for `EVP_AEAD_CTX_seal`/`_open` --
// the only two functions `seal`/`open` (both `&self`) call -- so
// concurrent use through `&AesGcm` is race-free.
unsafe impl Send for AesGcm {}
unsafe impl Sync for AesGcm {}

/// Copies `data` into the raw buffer pointed to by `ptr`, or does nothing
/// if `ptr` is null or `data` is empty.
///
/// This crate's `AesGcm` never needs to touch a raw pointer -- `seal`/
/// `open` work entirely on Rust slices -- but kryoptic's PKCS#11
/// integration layer (`crate::awslc::aes` in the kryoptic crate) does: a
/// PKCS#11 `CK_GCM_MESSAGE_PARAMS`'s `pIv`/`pTag` are raw C pointers into
/// caller-owned buffers that a generated IV or computed tag must be
/// written back into. This helper confines that single, narrowly-scoped
/// pointer write to this crate (mirroring how kryoptic's own
/// `crate::misc::bytes_to_vec` confines the read side of the same kind of
/// FFI boundary to one helper), so the integration layer itself only ever
/// needs one line of `unsafe` per call site, right where the caller-
/// supplied pointer's validity is actually known.
///
/// # Safety
///
/// `ptr`, unless null, must be valid for `data.len()` writes and
/// correctly aligned for `u8` (trivially satisfied for any non-null
/// pointer).
pub unsafe fn write_out(ptr: *mut u8, data: &[u8]) {
    if !ptr.is_null() && !data.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CipherMode {
    Ecb,
    Cbc,
    Ctr,
    Ofb,
    Cfb1,
    Cfb8,
    Cfb128,
}

fn cipher_mode_to_evp(
    mode: CipherMode,
    key_len: usize,
) -> Result<*const ffi::EVP_CIPHER, Error> {
    let cipher = unsafe {
        match (mode, key_len) {
            (CipherMode::Ecb, 16) => ffi::EVP_aes_128_ecb(),
            (CipherMode::Ecb, 24) => ffi::EVP_aes_192_ecb(),
            (CipherMode::Ecb, 32) => ffi::EVP_aes_256_ecb(),
            (CipherMode::Cbc, 16) => ffi::EVP_aes_128_cbc(),
            (CipherMode::Cbc, 24) => ffi::EVP_aes_192_cbc(),
            (CipherMode::Cbc, 32) => ffi::EVP_aes_256_cbc(),
            (CipherMode::Ctr, 16) => ffi::EVP_aes_128_ctr(),
            (CipherMode::Ctr, 24) => ffi::EVP_aes_192_ctr(),
            (CipherMode::Ctr, 32) => ffi::EVP_aes_256_ctr(),
            (CipherMode::Ofb, 16) => ffi::EVP_aes_128_ofb(),
            (CipherMode::Ofb, 24) => ffi::EVP_aes_192_ofb(),
            (CipherMode::Ofb, 32) => ffi::EVP_aes_256_ofb(),
            (CipherMode::Cfb1, 16) => ffi::EVP_aes_128_cfb1(),
            (CipherMode::Cfb1, 24) => ffi::EVP_aes_192_cfb1(),
            (CipherMode::Cfb1, 32) => ffi::EVP_aes_256_cfb1(),
            (CipherMode::Cfb8, 16) => ffi::EVP_aes_128_cfb8(),
            (CipherMode::Cfb8, 24) => ffi::EVP_aes_192_cfb8(),
            (CipherMode::Cfb8, 32) => ffi::EVP_aes_256_cfb8(),
            (CipherMode::Cfb128, 16) => ffi::EVP_aes_128_cfb128(),
            (CipherMode::Cfb128, 24) => ffi::EVP_aes_192_cfb128(),
            (CipherMode::Cfb128, 32) => ffi::EVP_aes_256_cfb128(),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        }
    };
    if cipher.is_null() {
        return Err(Error::new(ErrorKind::NullPtr));
    }
    Ok(cipher)
}

/// A single block-cipher operation (ECB/CBC/CTR/OFB/CFB*), wrapping AWS-LC's
/// classic streaming `EVP_CIPHER` API. Each instance is single-use and
/// single-direction: classic `EVP_CIPHER_CTX` is directional (init decides
/// which of the encrypt/decrypt key schedule AES uses — this only matters
/// for ECB/CBC, but the API doesn't let you mix `Encrypt*`/`Decrypt*` calls
/// regardless of mode, so `new` always takes an explicit direction and every
/// call after it must match). Create a fresh instance per encrypt/decrypt
/// call, matching how kryoptic's PKCS#11 `Encryption`/`Decryption`
/// operations are already structured (one object per `C_EncryptInit`/
/// `C_DecryptInit`).
#[derive(Debug)]
pub struct BlockCipher {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    encrypting: bool,
}

impl BlockCipher {
    /// `iv` is `None` for ECB (which has no IV); `Some(&[u8; 16])`-length
    /// slice for every other mode here (CFB1/CFB8/CFB128/OFB/CTR/CBC all
    /// use a 16-byte IV for AES). `encrypting` selects which of
    /// `EVP_EncryptInit_ex`/`EVP_DecryptInit_ex` this instance uses —
    /// afterward, only the matching `encrypt`/`decrypt` method may be
    /// called on it.
    pub fn new(
        mode: CipherMode,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
    ) -> Result<BlockCipher, Error> {
        let cipher = cipher_mode_to_evp(mode, key.len())?;
        let ctx = unsafe { ffi::EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let iv_ptr = iv.map_or(std::ptr::null(), |v| v.as_ptr());
        let ret = unsafe {
            if encrypting {
                ffi::EVP_EncryptInit_ex(
                    ctx,
                    cipher,
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    iv_ptr,
                )
            } else {
                ffi::EVP_DecryptInit_ex(
                    ctx,
                    cipher,
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    iv_ptr,
                )
            }
        };
        if ret != 1 {
            unsafe { ffi::EVP_CIPHER_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(BlockCipher { ctx, encrypting })
    }

    /// Encrypts `input` into `output`. `padding` enables PKCS#7 padding
    /// (only meaningful for CBC/ECB — the caller is responsible for only
    /// passing `true` for modes that support it). Panics (a programmer
    /// error, not a runtime condition) if this instance was constructed
    /// with `encrypting: false`.
    pub fn encrypt(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        padding: bool,
    ) -> Result<usize, Error> {
        assert!(
            self.encrypting,
            "BlockCipher: encrypt() on a decrypt-mode instance"
        );
        let needed = if padding {
            input.len() + 16
        } else {
            input.len()
        };
        if output.len() < needed {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        if unsafe { ffi::EVP_CIPHER_CTX_set_padding(self.ctx, padding as i32) }
            != 1
        {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut outl: i32 = 0;
        let ret = unsafe {
            ffi::EVP_EncryptUpdate(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
                input.as_ptr(),
                i32::try_from(input.len())
                    .map_err(|_| Error::new(ErrorKind::WrapperError))?,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut finall: i32 = 0;
        let ret = unsafe {
            ffi::EVP_EncryptFinal_ex(
                self.ctx,
                output[usize::try_from(outl).unwrap()..].as_mut_ptr(),
                &mut finall,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(usize::try_from(outl + finall).unwrap())
    }

    /// Decrypts `input` into `output`, mirroring `encrypt`. Panics if this
    /// instance was constructed with `encrypting: true`.
    pub fn decrypt(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        padding: bool,
    ) -> Result<usize, Error> {
        assert!(
            !self.encrypting,
            "BlockCipher: decrypt() on an encrypt-mode instance"
        );
        let needed = if padding {
            input.len() + 16
        } else {
            input.len()
        };
        if output.len() < needed {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        if unsafe { ffi::EVP_CIPHER_CTX_set_padding(self.ctx, padding as i32) }
            != 1
        {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut outl: i32 = 0;
        let ret = unsafe {
            ffi::EVP_DecryptUpdate(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
                input.as_ptr(),
                i32::try_from(input.len())
                    .map_err(|_| Error::new(ErrorKind::WrapperError))?,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut finall: i32 = 0;
        let ret = unsafe {
            ffi::EVP_DecryptFinal_ex(
                self.ctx,
                output[usize::try_from(outl).unwrap()..].as_mut_ptr(),
                &mut finall,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(usize::try_from(outl + finall).unwrap())
    }
}

impl Drop for BlockCipher {
    fn drop(&mut self) {
        unsafe { ffi::EVP_CIPHER_CTX_free(self.ctx) };
    }
}

// SAFETY: `BlockCipher` exclusively owns its `*mut EVP_CIPHER_CTX`, so
// Send is sound (moving it to another thread is fine; nothing else
// retains a pointer to it). Sync is technically sound too but not
// actually load-bearing: `encrypt`/`decrypt` both take `&mut self` (this
// type's internal `EVP_CIPHER_CTX` genuinely mutates across calls, unlike
// `AesGcm`/`AesCcm`'s one-shot primitives -- CBC/CTR/OFB/CFB* chaining
// state must persist between calls), so Rust's own borrow checker never
// allows two threads to call them concurrently through a shared `&Self`
// regardless of this impl; only `Send` (moving a fully-owned `BlockCipher`
// to another thread) is the practically meaningful half.
unsafe impl Send for BlockCipher {}
unsafe impl Sync for BlockCipher {}

fn aes_ccm_cipher(key_len: usize) -> Result<*const ffi::EVP_CIPHER, Error> {
    let cipher = unsafe {
        match key_len {
            16 => ffi::EVP_aes_128_ccm(),
            24 => ffi::EVP_aes_192_ccm(),
            32 => ffi::EVP_aes_256_ccm(),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        }
    };
    if cipher.is_null() {
        return Err(Error::new(ErrorKind::NullPtr));
    }
    Ok(cipher)
}

// Unlike `AesGcm` (which only holds an opaque `*mut ffi::EVP_AEAD_CTX`),
// `AesCcm` holds the raw AES key directly as `key: Vec<u8>`, so a derived
// `Debug` would print it in cleartext on any `{:?}` format of this type
// (same class of bug `AesKeyWrap`'s redacting `Debug` below fixes).
redacting_debug!(AesCcm {
    redact: [key],
    show: [tag_len],
});

pub struct AesCcm {
    key: Vec<u8>,
    tag_len: usize,
}

impl AesCcm {
    pub fn new(key: &[u8], tag_len: usize) -> Result<AesCcm, Error> {
        // Validates the key length is one aes_ccm_cipher() accepts.
        aes_ccm_cipher(key.len())?;
        Ok(AesCcm {
            key: key.to_vec(),
            tag_len,
        })
    }

    pub fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if out.len() < plaintext.len() + self.tag_len {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let cipher = aes_ccm_cipher(self.key.len())?;
        let ctx = unsafe { ffi::EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let result = (|| -> Result<usize, Error> {
            let tag_len_i32 = i32::try_from(self.tag_len)
                .map_err(|_| Error::new(ErrorKind::WrapperError))?;
            let pt_len_i32 = i32::try_from(plaintext.len())
                .map_err(|_| Error::new(ErrorKind::WrapperError))?;
            unsafe {
                if ffi::EVP_EncryptInit_ex(
                    ctx,
                    cipher,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_AEAD_SET_IVLEN,
                    i32::try_from(nonce.len())
                        .map_err(|_| Error::new(ErrorKind::WrapperError))?,
                    std::ptr::null_mut(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_AEAD_SET_TAG,
                    tag_len_i32,
                    std::ptr::null_mut(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_EncryptInit_ex(
                    ctx,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                let mut outl: i32 = 0;
                // Declare total plaintext length up front (CCM-specific).
                if ffi::EVP_EncryptUpdate(
                    ctx,
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    pt_len_i32,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_EncryptUpdate(
                    ctx,
                    std::ptr::null_mut(),
                    &mut outl,
                    aad.as_ptr(),
                    i32::try_from(aad.len())
                        .map_err(|_| Error::new(ErrorKind::WrapperError))?,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_EncryptUpdate(
                    ctx,
                    out.as_mut_ptr(),
                    &mut outl,
                    plaintext.as_ptr(),
                    pt_len_i32,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                let ctlen = usize::try_from(outl).unwrap();
                let mut finall: i32 = 0;
                if ffi::EVP_EncryptFinal_ex(
                    ctx,
                    out[ctlen..].as_mut_ptr(),
                    &mut finall,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                // CCM's EVP_EncryptFinal_ex is not expected to emit any
                // further ciphertext bytes (everything is already produced
                // by EVP_EncryptUpdate) -- `out[ctlen..]` is where the tag
                // gets written next. If AWS-LC ever reported otherwise,
                // proceeding would silently overwrite the start of the tag
                // with plaintext-derived bytes (real data corruption, not
                // just a debug-build assertion), so this is checked for
                // real rather than with `debug_assert!`.
                if finall != 0 {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_AEAD_GET_TAG,
                    tag_len_i32,
                    out[ctlen..].as_mut_ptr() as *mut std::os::raw::c_void,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                Ok(ctlen + self.tag_len)
            }
        })();
        unsafe { ffi::EVP_CIPHER_CTX_free(ctx) };
        result
    }

    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if out.len() < ciphertext.len() {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let cipher = aes_ccm_cipher(self.key.len())?;
        let ctx = unsafe { ffi::EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut tag_buf = tag.to_vec();
        let result = (|| -> Result<usize, Error> {
            let ct_len_i32 = i32::try_from(ciphertext.len())
                .map_err(|_| Error::new(ErrorKind::WrapperError))?;
            unsafe {
                if ffi::EVP_DecryptInit_ex(
                    ctx,
                    cipher,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_AEAD_SET_IVLEN,
                    i32::try_from(nonce.len())
                        .map_err(|_| Error::new(ErrorKind::WrapperError))?,
                    std::ptr::null_mut(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_AEAD_SET_TAG,
                    i32::try_from(tag_buf.len())
                        .map_err(|_| Error::new(ErrorKind::WrapperError))?,
                    tag_buf.as_mut_ptr() as *mut std::os::raw::c_void,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if ffi::EVP_DecryptInit_ex(
                    ctx,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                let mut outl: i32 = 0;
                if ffi::EVP_DecryptUpdate(
                    ctx,
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    ct_len_i32,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                // AAD MUST be fed on decrypt too -- the tag covers it. Omitting
                // this call makes tag verification legitimately (and
                // correctly) fail; it is not optional bookkeeping.
                if ffi::EVP_DecryptUpdate(
                    ctx,
                    std::ptr::null_mut(),
                    &mut outl,
                    aad.as_ptr(),
                    i32::try_from(aad.len())
                        .map_err(|_| Error::new(ErrorKind::WrapperError))?,
                ) != 1
                {
                    return Err(Error::new(ErrorKind::BackendError));
                }
                // For CCM, tag verification happens inside this call (its
                // return value IS the verification result) -- unlike GCM,
                // there is no separate Final call on the decrypt path.
                let ret = ffi::EVP_DecryptUpdate(
                    ctx,
                    out.as_mut_ptr(),
                    &mut outl,
                    ciphertext.as_ptr(),
                    ct_len_i32,
                );
                if ret != 1 {
                    return Err(Error::new(ErrorKind::VerifyFailed));
                }
                Ok(usize::try_from(outl).unwrap())
            }
        })();
        unsafe { ffi::EVP_CIPHER_CTX_free(ctx) };
        result
    }
}

impl OneShotAead for AesCcm {
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        AesCcm::seal(self, nonce, aad, plaintext, out)
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        AesCcm::open(self, nonce, aad, ciphertext, tag, out)
    }
}

impl Drop for AesCcm {
    fn drop(&mut self) {
        zeromem(&mut self.key);
    }
}

// SAFETY: `AesCcm` holds only immutable data (`key`, `tag_len`) after
// construction -- unlike `AesGcm`, it has no long-lived AWS-LC context
// object at all: `seal`/`open` each create their own fresh, function-
// local `EVP_CIPHER_CTX` via `EVP_CIPHER_CTX_new()` and free it before
// returning, never storing it in `self`. So concurrent `&self` calls
// never share any mutable AWS-LC state to race on; both impls are sound.
unsafe impl Send for AesCcm {}
unsafe impl Sync for AesCcm {}

/// The AES block size, and also RFC 5649's single-block special-case
/// threshold for its padded key wrap.
const AES_KW_BLOCK: usize = 16;

// `ffi::AES_KEY` (aws-lc-sys's `aes_key_st`) derives `Debug` over its own
// `rd_key: [u32; 60]` field -- the full AES round-key schedule, from
// which the original key-encryption key is trivially recoverable -- so a
// derived `Debug` here would print a KEK in cleartext on any `{:?}`
// format of this type.
redacting_debug!(AesKeyWrap {
    redact: [encrypt_key, decrypt_key],
    show: [],
});

pub struct AesKeyWrap {
    encrypt_key: ffi::AES_KEY,
    decrypt_key: ffi::AES_KEY,
}

impl AesKeyWrap {
    pub fn new(kek: &[u8]) -> Result<AesKeyWrap, Error> {
        let bits = u32::try_from(kek.len() * 8)
            .map_err(|_| Error::new(ErrorKind::WrapperError))?;
        let mut encrypt_key: ffi::AES_KEY = unsafe { std::mem::zeroed() };
        let mut decrypt_key: ffi::AES_KEY = unsafe { std::mem::zeroed() };
        if unsafe {
            ffi::AES_set_encrypt_key(kek.as_ptr(), bits, &mut encrypt_key)
        } != 0
        {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        if unsafe {
            ffi::AES_set_decrypt_key(kek.as_ptr(), bits, &mut decrypt_key)
        } != 0
        {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        Ok(AesKeyWrap {
            encrypt_key,
            decrypt_key,
        })
    }

    /// Plain RFC 3394 key wrap. `data` must be a multiple of 8 bytes and at
    /// least 16 bytes (the caller -- src/awslc/aes.rs -- is responsible for
    /// applying PKCS7 padding first for CKM_AES_KEY_WRAP_PKCS7, since that
    /// mechanism uses plain KW under PKCS7-padded input, not KWP's AIV
    /// mechanism). Uses RFC 3394's default IV; see [`Self::wrap_with_iv`]
    /// for a caller-supplied one.
    pub fn wrap(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.wrap_with_iv(None, data, out)
    }

    /// Same as [`Self::wrap`], but with an explicit 8-byte IV instead of
    /// RFC 3394's default (`None` still means "use the default"). Also the
    /// building block [`Self::wrap_padded_with_prefix`] uses to implement a
    /// custom RFC 5649 AIV, since AWS-LC's own `AES_wrap_key_padded` always
    /// hardcodes RFC 5649's fixed constant and has no such parameter.
    pub fn wrap_with_iv(
        &self,
        iv: Option<&[u8; 8]>,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if out.len() < data.len() + 8 {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let iv_ptr = match iv {
            Some(v) => v.as_ptr(),
            None => std::ptr::null(),
        };
        let n = unsafe {
            ffi::AES_wrap_key(
                &self.encrypt_key,
                iv_ptr,
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
            )
        };
        if n <= 0 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(usize::try_from(n).unwrap())
    }

    /// Uses RFC 3394's default IV; see [`Self::unwrap_with_iv`] for a
    /// caller-supplied one.
    pub fn unwrap(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.unwrap_with_iv(None, data, out)
    }

    /// Same as [`Self::unwrap`], but verifies against an explicit 8-byte IV
    /// instead of RFC 3394's default (`None` still means "use the
    /// default"). Also the building block [`Self::unwrap_padded_with_prefix`]
    /// uses to verify a custom RFC 5649 AIV.
    pub fn unwrap_with_iv(
        &self,
        iv: Option<&[u8; 8]>,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if data.len() < 8 || out.len() < data.len() - 8 {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let iv_ptr = match iv {
            Some(v) => v.as_ptr(),
            None => std::ptr::null(),
        };
        let n = unsafe {
            ffi::AES_unwrap_key(
                &self.decrypt_key,
                iv_ptr,
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
            )
        };
        if n <= 0 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(usize::try_from(n).unwrap())
    }

    /// RFC 5649 key wrap with padding (handles arbitrary-length input
    /// itself via its alternative IV encoding).
    pub fn wrap_padded(
        &self,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut outlen: usize = 0;
        let n = unsafe {
            ffi::AES_wrap_key_padded(
                &self.encrypt_key,
                out.as_mut_ptr(),
                &mut outlen,
                out.len(),
                data.as_ptr(),
                data.len(),
            )
        };
        if n != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(outlen)
    }

    pub fn unwrap_padded(
        &self,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut outlen: usize = 0;
        let n = unsafe {
            ffi::AES_unwrap_key_padded(
                &self.decrypt_key,
                out.as_mut_ptr(),
                &mut outlen,
                out.len(),
                data.as_ptr(),
                data.len(),
            )
        };
        if n != 1 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(outlen)
    }

    /// RFC 5649 key wrap with padding, using a caller-supplied 4-byte AIV
    /// prefix instead of RFC 5649 section 3's fixed constant (0xA65959A6).
    /// Mirrors AWS-LC's own `AES_wrap_key_padded`
    /// (`crypto/fipsmodule/aes/key_wrap.c`) exactly -- that C function
    /// itself builds an 8-byte AIV (a fixed 4-byte constant || the
    /// big-endian input length) and, for inputs over 8 bytes, feeds it
    /// straight into `AES_wrap_key`'s own `iv` parameter; for inputs of 8
    /// bytes or fewer it does one raw AES-ECB block encryption of
    /// `AIV || zero-padded input` instead. Both cases are reproduced here
    /// using [`Self::wrap_with_iv`] (which exposes that same `iv`
    /// parameter) and a direct `AES_encrypt` call, with only the AIV's
    /// leading 4 bytes swapped for `prefix`.
    pub fn wrap_padded_with_prefix(
        &self,
        prefix: [u8; 4],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if data.is_empty() || data.len() > u32::MAX as usize {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let mut aiv = [0u8; 8];
        aiv[..4].copy_from_slice(&prefix);
        aiv[4..].copy_from_slice(&(data.len() as u32).to_be_bytes());

        if data.len() <= 8 {
            if out.len() < AES_KW_BLOCK {
                return Err(Error::new(ErrorKind::BufferSize));
            }
            let mut block = [0u8; AES_KW_BLOCK];
            block[..8].copy_from_slice(&aiv);
            block[8..8 + data.len()].copy_from_slice(data);
            unsafe {
                ffi::AES_encrypt(
                    block.as_ptr(),
                    out.as_mut_ptr(),
                    &self.encrypt_key,
                );
            }
            zeromem(&mut block);
            return Ok(AES_KW_BLOCK);
        }

        let padded_len = (data.len() + 7) & !7;
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);
        let result = self.wrap_with_iv(Some(&aiv), &padded, out);
        zeromem(&mut padded);
        result
    }

    /// Inverse of [`Self::wrap_padded_with_prefix`]. Since AWS-LC exposes
    /// no way to recover the AIV an unwrap actually computed (only whether
    /// it matches a caller-supplied one, via the public `AES_unwrap_key`),
    /// and the true input length isn't known until after unwrapping, this
    /// tries each of the (at most 8) lengths RFC 5649 padding allows for
    /// this ciphertext size as a candidate AIV, via [`Self::unwrap_with_iv`]
    /// -- which performs AWS-LC's own real, tested unwrap-and-verify for
    /// each -- and accepts the one that both verifies and has all-zero
    /// padding bytes beyond the claimed length. This still does the exact
    /// same verification RFC 5649 requires; it just restructures AWS-LC's
    /// internal "compute once, compare once" as "compare against each
    /// candidate", since only the former is reachable through AWS-LC's
    /// public API.
    pub fn unwrap_padded_with_prefix(
        &self,
        prefix: [u8; 4],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if data.len() < AES_KW_BLOCK || data.len() % 8 != 0 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }

        if data.len() == AES_KW_BLOCK {
            let mut block = [0u8; AES_KW_BLOCK];
            unsafe {
                ffi::AES_decrypt(
                    data.as_ptr(),
                    block.as_mut_ptr(),
                    &self.decrypt_key,
                );
            }
            let claimed_len =
                u32::from_be_bytes(block[4..8].try_into().unwrap()) as usize;
            let ok = block[..4] == prefix
                && (1..=8).contains(&claimed_len)
                && block[8 + claimed_len..16].iter().all(|&b| b == 0);
            if !ok {
                zeromem(&mut block);
                return Err(Error::new(ErrorKind::VerifyFailed));
            }
            if out.len() < claimed_len {
                zeromem(&mut block);
                return Err(Error::new(ErrorKind::BufferSize));
            }
            out[..claimed_len].copy_from_slice(&block[8..8 + claimed_len]);
            zeromem(&mut block);
            return Ok(claimed_len);
        }

        let padded_len = data.len() - 8;
        let min_len = padded_len - 7;
        let mut padded_out = vec![0u8; padded_len];
        let mut found: Option<usize> = None;
        for l in min_len..=padded_len {
            let mut aiv = [0u8; 8];
            aiv[..4].copy_from_slice(&prefix);
            aiv[4..].copy_from_slice(&(l as u32).to_be_bytes());
            if self
                .unwrap_with_iv(Some(&aiv), data, &mut padded_out)
                .is_ok()
                && padded_out[l..].iter().all(|&b| b == 0)
            {
                found = Some(l);
                break;
            }
        }
        let result = match found {
            Some(l) if out.len() >= l => {
                out[..l].copy_from_slice(&padded_out[..l]);
                Ok(l)
            }
            Some(_) => Err(Error::new(ErrorKind::BufferSize)),
            None => Err(Error::new(ErrorKind::VerifyFailed)),
        };
        zeromem(&mut padded_out);
        result
    }
}

impl Drop for AesKeyWrap {
    fn drop(&mut self) {
        let bytes = |k: &mut ffi::AES_KEY| unsafe {
            std::slice::from_raw_parts_mut(
                k as *mut _ as *mut u8,
                std::mem::size_of::<ffi::AES_KEY>(),
            )
        };
        zeromem(bytes(&mut self.encrypt_key));
        zeromem(bytes(&mut self.decrypt_key));
    }
}

// SAFETY: unlike the EVP-context-based types above, `AesKeyWrap` holds
// only two fixed-size `AES_KEY` key-schedule structs (set once, at
// construction) -- no pointer, no shared mutable context object at all.
// Every `wrap`/`unwrap` variant passes `&self.encrypt_key`/`&self.
// decrypt_key` to `AES_wrap_key`/`AES_unwrap_key`, both of which take a
// `const AES_KEY*` and are pure functions of their (immutable, per-call)
// input -- there is no internal state for concurrent calls to race on.
// Both impls are sound.
unsafe impl Send for AesKeyWrap {}
unsafe impl Sync for AesKeyWrap {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"associated-data";
        let plaintext = b"hello world, this is a test message";

        let gcm = AesGcm::new(&key, 8).unwrap();
        let mut sealed = vec![0u8; plaintext.len() + 8];
        let n = gcm.seal(&nonce, aad, plaintext, &mut sealed).unwrap();
        assert_eq!(n, plaintext.len() + 8);

        let ciphertext = &sealed[..plaintext.len()];
        let tag = &sealed[plaintext.len()..];
        assert_ne!(ciphertext, &plaintext[..]);

        let mut recovered = vec![0u8; plaintext.len()];
        let n = gcm
            .open(&nonce, aad, ciphertext, tag, &mut recovered)
            .unwrap();
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn round_trip_aes_192() {
        let key = [0x77u8; 24];
        let nonce = [0x88u8; 12];
        let aad = b"associated-data";
        let plaintext = b"hello world, this is a test message";

        let gcm = AesGcm::new(&key, 8).unwrap();
        let mut sealed = vec![0u8; plaintext.len() + 8];
        let n = gcm.seal(&nonce, aad, plaintext, &mut sealed).unwrap();
        assert_eq!(n, plaintext.len() + 8);

        let ciphertext = &sealed[..plaintext.len()];
        let tag = &sealed[plaintext.len()..];
        assert_ne!(ciphertext, &plaintext[..]);

        let mut recovered = vec![0u8; plaintext.len()];
        let n = gcm
            .open(&nonce, aad, ciphertext, tag, &mut recovered)
            .unwrap();
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"aad";
        let plaintext = b"secret data";

        let gcm = AesGcm::new(&key, 8).unwrap();
        let mut sealed = vec![0u8; plaintext.len() + 8];
        gcm.seal(&nonce, aad, plaintext, &mut sealed).unwrap();

        let ciphertext = sealed[..plaintext.len()].to_vec();
        let mut tag = sealed[plaintext.len()..].to_vec();
        tag[0] ^= 0xFF;

        let mut out = vec![0u8; plaintext.len()];
        assert!(gcm.open(&nonce, aad, &ciphertext, &tag, &mut out).is_err());
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];
        let plaintext = b"secret data";

        let gcm = AesGcm::new(&key, 8).unwrap();
        let mut sealed = vec![0u8; plaintext.len() + 8];
        gcm.seal(&nonce, b"correct-aad", plaintext, &mut sealed)
            .unwrap();

        let ciphertext = sealed[..plaintext.len()].to_vec();
        let tag = sealed[plaintext.len()..].to_vec();

        let mut out = vec![0u8; plaintext.len()];
        assert!(gcm
            .open(&nonce, b"wrong-aad", &ciphertext, &tag, &mut out)
            .is_err());
    }

    #[test]
    fn cbc_round_trip_no_padding() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let pt = b"0123456789abcdef"; // exactly one 16-byte block
        let mut ct = [0u8; 16];
        let n = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, false)
            .unwrap();
        assert_eq!(n, 16);
        assert_ne!(&ct[..], &pt[..]);

        let mut pt2 = [0u8; 16];
        let n2 = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), false)
            .unwrap()
            .decrypt(&ct, &mut pt2, false)
            .unwrap();
        assert_eq!(n2, 16);
        assert_eq!(&pt2[..], &pt[..]);
    }

    #[test]
    fn cbc_round_trip_aes192_no_padding() {
        // Regression test for a bug where `cipher_mode_to_evp` only
        // matched 16/32-byte keys, so a 24-byte (AES-192) key fell through
        // to its `_` arm and every classic block-cipher mode returned
        // CKR_GENERAL_ERROR for AES-192.
        let key = [0x99u8; 24];
        let iv = [0xaau8; 16];
        let pt = b"0123456789abcdef"; // exactly one 16-byte block
        let mut ct = [0u8; 16];
        let n = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, false)
            .unwrap();
        assert_eq!(n, 16);
        assert_ne!(&ct[..], &pt[..]);

        let mut pt2 = [0u8; 16];
        let n2 = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), false)
            .unwrap()
            .decrypt(&ct, &mut pt2, false)
            .unwrap();
        assert_eq!(n2, 16);
        assert_eq!(&pt2[..], &pt[..]);
    }

    #[test]
    fn ctr_round_trip_aes192() {
        let key = [0xbbu8; 24];
        let iv = [0xccu8; 16];
        let pt = b"counter mode plaintext, any length works";
        let mut ct = vec![0u8; pt.len()];
        let n = BlockCipher::new(CipherMode::Ctr, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, false)
            .unwrap();
        assert_eq!(n, pt.len());
        assert_ne!(&ct[..n], &pt[..]);

        let mut pt2 = vec![0u8; pt.len()];
        let n2 = BlockCipher::new(CipherMode::Ctr, &key, Some(&iv), false)
            .unwrap()
            .decrypt(&ct[..n], &mut pt2, false)
            .unwrap();
        assert_eq!(&pt2[..n2], &pt[..]);
    }

    #[test]
    fn cbc_pad_round_trip_partial_block() {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let pt = b"not a full block"; // 16 bytes exactly, but padding=true still adds a full pad block on encrypt
        let mut ct = [0u8; 32];
        let n = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, true)
            .unwrap();
        assert_eq!(n, 32); // one data block + one full pad block (PKCS#7 padding)

        let mut pt2 = [0u8; 48]; // needs at least input.len() + 16 for decrypt with padding=true
        let n2 = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), false)
            .unwrap()
            .decrypt(&ct[..n], &mut pt2, true)
            .unwrap();
        assert_eq!(&pt2[..n2], &pt[..]);
    }

    #[test]
    fn ctr_round_trip() {
        let key = [0x55u8; 32];
        let iv = [0x66u8; 16];
        let pt = b"counter mode plaintext, any length works";
        let mut ct = vec![0u8; pt.len()];
        let n = BlockCipher::new(CipherMode::Ctr, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, false)
            .unwrap();
        assert_eq!(n, pt.len());
        assert_ne!(&ct[..n], &pt[..]);

        let mut pt2 = vec![0u8; pt.len()];
        let n2 = BlockCipher::new(CipherMode::Ctr, &key, Some(&iv), false)
            .unwrap()
            .decrypt(&ct[..n], &mut pt2, false)
            .unwrap();
        assert_eq!(&pt2[..n2], &pt[..]);
    }

    #[test]
    fn ecb_round_trip_aes128() {
        // NIST SP 800-38A F.1.1 ECB-AES128 vector, block 1.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected_ct = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
            0xf3, 0x24, 0x66, 0xef, 0x97,
        ];
        let mut ct = [0u8; 16];
        let n = BlockCipher::new(CipherMode::Ecb, &key, None, true)
            .unwrap()
            .encrypt(&pt, &mut ct, false)
            .unwrap();
        assert_eq!(n, 16);
        assert_eq!(ct, expected_ct);
    }

    #[test]
    fn ccm_round_trip() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"header";
        let pt = b"ccm plaintext msg";
        let tag_len = 8;

        let mut sealed = vec![0u8; pt.len() + tag_len];
        let ccm = AesCcm::new(&key, tag_len).unwrap();
        let n = ccm.seal(&nonce, aad, pt, &mut sealed).unwrap();
        assert_eq!(n, pt.len() + tag_len);

        let ciphertext = &sealed[..pt.len()];
        let tag = &sealed[pt.len()..];
        assert_ne!(ciphertext, &pt[..]);

        let mut recovered = vec![0u8; pt.len()];
        let n2 = ccm
            .open(&nonce, aad, ciphertext, tag, &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..n2], &pt[..]);
    }

    #[test]
    fn ccm_tampered_tag_rejected() {
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        let aad = b"aad";
        let pt = b"secret";
        let tag_len = 8;

        let mut sealed = vec![0u8; pt.len() + tag_len];
        let ccm = AesCcm::new(&key, tag_len).unwrap();
        ccm.seal(&nonce, aad, pt, &mut sealed).unwrap();

        let ciphertext = sealed[..pt.len()].to_vec();
        let mut tag = sealed[pt.len()..].to_vec();
        tag[0] ^= 0xFF;

        let mut out = vec![0u8; pt.len()];
        assert!(ccm.open(&nonce, aad, &ciphertext, &tag, &mut out).is_err());
    }

    #[test]
    fn ccm_wrong_aad_rejected() {
        let key = [0x99u8; 32];
        let nonce = [0xaau8; 12];
        let pt = b"secret data";
        let tag_len = 8;

        let mut sealed = vec![0u8; pt.len() + tag_len];
        let ccm = AesCcm::new(&key, tag_len).unwrap();
        ccm.seal(&nonce, b"right-aad", pt, &mut sealed).unwrap();

        let ciphertext = sealed[..pt.len()].to_vec();
        let tag = sealed[pt.len()..].to_vec();

        let mut out = vec![0u8; pt.len()];
        assert!(ccm
            .open(&nonce, b"wrong-aad", &ciphertext, &tag, &mut out)
            .is_err());
    }

    #[test]
    fn undersized_output_buffer_rejected() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let pt = b"0123456789abcdef"; // 16 bytes
        let mut ct = [0u8; 10]; // too small: needs at least input.len() (with padding=false)
        let result = BlockCipher::new(CipherMode::Cbc, &key, Some(&iv), true)
            .unwrap()
            .encrypt(pt, &mut ct, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BufferSize);
    }

    #[test]
    fn kw_round_trip_rfc3394_vector() {
        // RFC 3394 Section 4.1 test vector: 128-bit KEK wrapping a 128-bit
        // key.
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let key_data = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
            0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected_wrapped = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B,
            0xD8, 0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2,
            0xCF, 0xE5,
        ];
        let kw = AesKeyWrap::new(&kek).unwrap();
        let mut wrapped = [0u8; 24];
        let n = kw.wrap(&key_data, &mut wrapped).unwrap();
        assert_eq!(n, 24);
        assert_eq!(wrapped, expected_wrapped);

        let mut unwrapped = [0u8; 16];
        let n2 = kw.unwrap(&wrapped, &mut unwrapped).unwrap();
        assert_eq!(n2, 16);
        assert_eq!(unwrapped, key_data);
    }

    #[test]
    fn kwp_round_trip() {
        let kek = [0x11u8; 32];
        let key_data = b"odd length key material, not a multiple of 8";
        let kw = AesKeyWrap::new(&kek).unwrap();
        let mut wrapped = vec![0u8; key_data.len() + 16];
        let n = kw.wrap_padded(key_data, &mut wrapped).unwrap();

        let mut unwrapped = vec![0u8; n];
        let n2 = kw.unwrap_padded(&wrapped[..n], &mut unwrapped).unwrap();
        assert_eq!(&unwrapped[..n2], &key_data[..]);
    }

    /// RFC 5649's own fixed constant, matching AWS-LC's `kPaddingConstant`
    /// (`crypto/fipsmodule/aes/key_wrap.c`) -- used to check that the
    /// custom-prefix path produces byte-identical output to (and correctly
    /// unwraps output from) AWS-LC's own trusted `AES_wrap_key_padded`/
    /// `AES_unwrap_key_padded` when given that same default prefix.
    const RFC5649_DEFAULT_PREFIX: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

    #[test]
    fn kwp_custom_prefix_matches_default_when_prefix_is_default() {
        let kek = [0x22u8; 16];
        let kw = AesKeyWrap::new(&kek).unwrap();
        for key_data in [
            &b"x"[..],
            &b"exactly8"[..],
            &b"odd length key material, not a multiple of 8"[..],
            &[0x5Au8; 32][..],
        ] {
            let mut wrapped_ref = vec![0u8; key_data.len() + 16];
            let n_ref = kw.wrap_padded(key_data, &mut wrapped_ref).unwrap();

            let mut wrapped_custom = vec![0u8; key_data.len() + 16];
            let n_custom = kw
                .wrap_padded_with_prefix(
                    RFC5649_DEFAULT_PREFIX,
                    key_data,
                    &mut wrapped_custom,
                )
                .unwrap();
            assert_eq!(&wrapped_custom[..n_custom], &wrapped_ref[..n_ref]);

            // And the custom-prefix unwrap must recover AWS-LC's own
            // wrapped output.
            let mut unwrapped = vec![0u8; key_data.len()];
            let n2 = kw
                .unwrap_padded_with_prefix(
                    RFC5649_DEFAULT_PREFIX,
                    &wrapped_ref[..n_ref],
                    &mut unwrapped,
                )
                .unwrap();
            assert_eq!(&unwrapped[..n2], key_data);
        }
    }

    #[test]
    fn kwp_custom_prefix_round_trip() {
        let kek = [0x33u8; 24];
        let kw = AesKeyWrap::new(&kek).unwrap();
        let prefix = [0xCC, 0xCC, 0xCC, 0xCC];
        for key_data in [
            &b"x"[..],
            &b"exactly8"[..],
            &b"a custom-IV wrapped RSA key, e.g."[..],
        ] {
            let mut wrapped = vec![0u8; key_data.len() + 16];
            let n = kw
                .wrap_padded_with_prefix(prefix, key_data, &mut wrapped)
                .unwrap();

            let mut unwrapped = vec![0u8; key_data.len()];
            let n2 = kw
                .unwrap_padded_with_prefix(
                    prefix,
                    &wrapped[..n],
                    &mut unwrapped,
                )
                .unwrap();
            assert_eq!(&unwrapped[..n2], key_data);

            // A different prefix than the one used to wrap must not verify.
            let mut rejected = vec![0u8; key_data.len()];
            assert!(kw
                .unwrap_padded_with_prefix(
                    RFC5649_DEFAULT_PREFIX,
                    &wrapped[..n],
                    &mut rejected,
                )
                .is_err());
        }
    }

    #[test]
    fn kw_custom_iv_round_trip_and_rejects_wrong_iv() {
        let kek = [0x44u8; 16];
        let kw = AesKeyWrap::new(&kek).unwrap();
        let key_data = [0xABu8; 16];
        let iv = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let mut wrapped = [0u8; 24];
        let n = kw.wrap_with_iv(Some(&iv), &key_data, &mut wrapped).unwrap();
        assert_eq!(n, 24);

        // Default-IV unwrap of a custom-IV wrap must fail the IV check.
        let mut out = [0u8; 16];
        assert!(kw.unwrap(&wrapped, &mut out).is_err());

        let n2 = kw.unwrap_with_iv(Some(&iv), &wrapped, &mut out).unwrap();
        assert_eq!(n2, 16);
        assert_eq!(out, key_data);
    }
}
