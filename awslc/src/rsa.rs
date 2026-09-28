// RSA, wrapping AWS-LC's classic RSA_* API.

use crate::cipher::{zeromem, SecretBuf};
use crate::error::{Error, ErrorKind};
use crate::ffi;

#[derive(Debug)]
pub struct RsaKey {
    rsa: *mut ffi::RSA,
}

// SAFETY: `RsaKey` exclusively owns its `*mut RSA` (never aliased by any
// other live reference), so moving it across threads (Send) is sound.
//
// Sync additionally requires that concurrent calls through `&RsaKey` from
// multiple threads are race-free. AWS-LC's `include/openssl/rsa.h` states
// this directly: "An |RSA| object represents a public or private RSA key.
// A given object may be used concurrently on multiple threads by
// non-mutating functions, provided no other thread is concurrently
// calling a mutating function" -- and separately, for the encrypt/
// decrypt/sign/verify functions this wrapper's `&self` methods call:
// "These functions are considered non-mutating for thread-safety purposes
// and may be used concurrently." No method reachable from `&self` here
// calls a mutating (non-`const RSA*`) function, so both impls are
// justified.
unsafe impl Send for RsaKey {}
unsafe impl Sync for RsaKey {}

impl Drop for RsaKey {
    fn drop(&mut self) {
        unsafe { ffi::RSA_free(self.rsa) };
    }
}

impl RsaKey {
    /// Generates a key with the default public exponent (F4 / 65537).
    /// Delegates to `generate_with_exponent`, which was added so kryoptic's
    /// integration layer (`src/awslc/rsa.rs`) can honor a caller-supplied
    /// `CKA_PUBLIC_EXPONENT` from a `C_GenerateKeyPair` template rather than
    /// always silently generating an F4 key regardless of what was
    /// requested -- that mismatch would leave a key's stored
    /// `CKA_PUBLIC_EXPONENT` attribute inconsistent with the modulus/private
    /// exponent AWS-LC actually generated.
    pub fn generate(bits: i32) -> Result<RsaKey, Error> {
        // RSA_F4 = 65537 = 0x01_00_01, big-endian.
        Self::generate_with_exponent(bits, &[0x01, 0x00, 0x01])
    }

    /// Generates a key with a caller-chosen public exponent `e` (raw
    /// big-endian bytes, e.g. from `CKA_PUBLIC_EXPONENT`).
    pub fn generate_with_exponent(
        bits: i32,
        e: &[u8],
    ) -> Result<RsaKey, Error> {
        let rsa = unsafe { ffi::RSA_new() };
        if rsa.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let e_bn = match bin_to_bn(e) {
            Ok(bn) => bn,
            Err(err) => {
                unsafe { ffi::RSA_free(rsa) };
                return Err(err);
            }
        };
        let gen_ok = unsafe {
            ffi::RSA_generate_key_ex(rsa, bits, e_bn, std::ptr::null_mut())
        } == 1;
        unsafe { ffi::BN_free(e_bn) };
        if !gen_ok {
            unsafe { ffi::RSA_free(rsa) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(RsaKey { rsa })
    }

    /// Constructs a public-key-only `RsaKey` from raw big-endian modulus
    /// and public-exponent bytes (e.g. from CKA_MODULUS/CKA_PUBLIC_EXPONENT).
    ///
    /// `RSA_new_public_key` takes `const BIGNUM *` parameters and never
    /// takes ownership of them, on either success or failure -- confirmed
    /// against AWS-LC's own vendored source
    /// (`crypto/fipsmodule/rsa/rsa.c`): it deep-copies each argument via
    /// its internal `bn_dup_into` helper (itself a thin wrapper around
    /// `BN_dup`) into fields of the *new* `RSA` object it allocates, rather
    /// than storing the caller's pointers. So `n_bn`/`e_bn` remain owned by
    /// this function and must always be freed here, unconditionally,
    /// regardless of whether the call above succeeded or failed.
    pub fn from_public_components(n: &[u8], e: &[u8]) -> Result<RsaKey, Error> {
        let n_bn = bin_to_bn(n)?;
        let e_bn = match bin_to_bn(e) {
            Ok(bn) => bn,
            Err(err) => {
                unsafe { ffi::BN_free(n_bn) };
                return Err(err);
            }
        };
        let rsa = unsafe { ffi::RSA_new_public_key(n_bn, e_bn) };
        unsafe {
            ffi::BN_free(n_bn);
            ffi::BN_free(e_bn);
        }
        if rsa.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(RsaKey { rsa })
    }

    /// Constructs a private-key `RsaKey` from raw big-endian component
    /// bytes. `crt` is `Some((p, q, dmp1, dmq1, iqmp))` when the caller has
    /// CRT parameters (the common case), or `None` when they're absent --
    /// PKCS#11 makes them optional on a private key object, and AWS-LC has
    /// a dedicated constructor for that case (`RSA_new_private_key_no_crt`).
    ///
    /// Same ownership note as `from_public_components` above:
    /// `RSA_new_private_key`/`RSA_new_private_key_no_crt` take `const
    /// BIGNUM *` parameters and deep-copy every one of them (via
    /// `bn_dup_into`/`BN_dup`, confirmed in AWS-LC's
    /// `crypto/fipsmodule/rsa/rsa.c`) into the new `RSA` object, on both
    /// the success and failure paths. So every BIGNUM built here remains
    /// ours to free, unconditionally, after each call.
    pub fn from_private_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        crt: Option<(&[u8], &[u8], &[u8], &[u8], &[u8])>,
    ) -> Result<RsaKey, Error> {
        // `n`/`e` are public and freed with plain `BN_free`; every other
        // BIGNUM here (`d`, and the CRT parameters) holds private key
        // material and is scrubbed with `BN_clear_free` before the
        // underlying allocation is released, on every exit path -- freeing
        // it unscrubbed would leave the private exponent/CRT parameters
        // readable in freed heap memory even though the RSA_new_private_key*
        // calls below deep-copy them into the new `RSA` object.
        let n_bn = bin_to_bn(n)?;
        let e_bn =
            bin_to_bn(e).inspect_err(|_| unsafe { ffi::BN_free(n_bn) })?;
        let d_bn = bin_to_bn(d).inspect_err(|_| unsafe {
            ffi::BN_free(n_bn);
            ffi::BN_free(e_bn);
        })?;

        let rsa = match crt {
            None => unsafe {
                ffi::RSA_new_private_key_no_crt(n_bn, e_bn, d_bn)
            },
            Some((p, q, dmp1, dmq1, iqmp)) => {
                // Each of these BIGNUM conversions can fail independently;
                // free everything allocated so far on any failure.
                let result = (|| -> Result<*mut ffi::RSA, Error> {
                    let p_bn = bin_to_bn(p)?;
                    let q_bn = bin_to_bn(q)
                        .inspect_err(|_| unsafe { ffi::BN_clear_free(p_bn) })?;
                    let dmp1_bn = bin_to_bn(dmp1).inspect_err(|_| unsafe {
                        ffi::BN_clear_free(p_bn);
                        ffi::BN_clear_free(q_bn);
                    })?;
                    let dmq1_bn = bin_to_bn(dmq1).inspect_err(|_| unsafe {
                        ffi::BN_clear_free(p_bn);
                        ffi::BN_clear_free(q_bn);
                        ffi::BN_clear_free(dmp1_bn);
                    })?;
                    let iqmp_bn = bin_to_bn(iqmp).inspect_err(|_| unsafe {
                        ffi::BN_clear_free(p_bn);
                        ffi::BN_clear_free(q_bn);
                        ffi::BN_clear_free(dmp1_bn);
                        ffi::BN_clear_free(dmq1_bn);
                    })?;
                    let rsa = unsafe {
                        ffi::RSA_new_private_key(
                            n_bn, e_bn, d_bn, p_bn, q_bn, dmp1_bn, dmq1_bn,
                            iqmp_bn,
                        )
                    };
                    unsafe {
                        ffi::BN_clear_free(p_bn);
                        ffi::BN_clear_free(q_bn);
                        ffi::BN_clear_free(dmp1_bn);
                        ffi::BN_clear_free(dmq1_bn);
                        ffi::BN_clear_free(iqmp_bn);
                    }
                    Ok(rsa)
                })();
                match result {
                    Ok(rsa) => rsa,
                    Err(e) => {
                        unsafe {
                            ffi::BN_free(n_bn);
                            ffi::BN_free(e_bn);
                            ffi::BN_clear_free(d_bn);
                        }
                        return Err(e);
                    }
                }
            }
        };

        unsafe {
            ffi::BN_free(n_bn);
            ffi::BN_free(e_bn);
            ffi::BN_clear_free(d_bn);
        }
        if rsa.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(RsaKey { rsa })
    }

    pub fn key_size_bytes(&self) -> usize {
        unsafe { ffi::RSA_size(self.rsa) as usize }
    }

    pub fn modulus(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_n(self.rsa) })
    }
    pub fn public_exponent(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_e(self.rsa) })
    }
    pub fn private_exponent(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_d(self.rsa) })
    }
    pub fn prime1(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_p(self.rsa) })
    }
    pub fn prime2(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_q(self.rsa) })
    }
    pub fn exponent1(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_dmp1(self.rsa) })
    }
    pub fn exponent2(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_dmq1(self.rsa) })
    }
    pub fn coefficient(&self) -> Vec<u8> {
        bn_to_vec(unsafe { ffi::RSA_get0_iqmp(self.rsa) })
    }

    /// PKCS#1 v1.5 sign. `hash_nid` (e.g. `ffi::NID_sha256`) identifies the
    /// digest algorithm that produced `digest`; the DigestInfo DER prefix
    /// is constructed internally by AWS-LC.
    pub fn sign_pkcs1(
        &self,
        hash_nid: i32,
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; self.key_size_bytes()];
        let mut sig_len: u32 = 0;
        let ret = unsafe {
            ffi::RSA_sign(
                hash_nid,
                digest.as_ptr(),
                digest.len(),
                sig.as_mut_ptr(),
                &mut sig_len,
                self.rsa,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    pub fn verify_pkcs1(
        &self,
        hash_nid: i32,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let ret = unsafe {
            ffi::RSA_verify(
                hash_nid,
                digest.as_ptr(),
                digest.len(),
                sig.as_ptr(),
                sig.len(),
                self.rsa,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(())
    }

    /// PKCS#1 v1.5 sign with padding applied directly to `message`, with
    /// *no* DigestInfo wrapper and no hash-algorithm identifier embedded --
    /// this is a different construction than `sign_pkcs1` above (RFC 8017's
    /// "block type 1" EMSA-PKCS1-v1_5 padding of the caller's exact bytes,
    /// vs. `sign_pkcs1`'s DigestInfo-wrapped construction). PKCS#11's plain
    /// `CKM_RSA_PKCS` sign mechanism needs this raw form: it pads and signs
    /// whatever bytes the caller supplies (typically a DigestInfo they built
    /// themselves), without AWS-LC adding a second one.
    ///
    /// Added for kryoptic's integration layer (`src/awslc/rsa.rs`), which
    /// wires `CKM_RSA_PKCS`'s `Sign`/`Verify` framing distinctly from its
    /// combined-hash mechanisms (`CKM_SHA256_RSA_PKCS` etc., which do use
    /// `sign_pkcs1`). Confirmed against AWS-LC's `RSA_sign_raw` doc comment
    /// (`include/openssl/rsa.h`): with `RSA_PKCS1_PADDING`, it "wraps `in`
    /// with the padding portion of RSASSA-PKCS1-v1_5 and then performs the
    /// raw private key operation. The caller is responsible for hashing the
    /// input and wrapping it in a DigestInfo structure" -- exactly the
    /// building block this mechanism needs.
    pub fn sign_pkcs1_raw(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; self.key_size_bytes()];
        let mut sig_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_sign_raw(
                self.rsa,
                &mut sig_len,
                sig.as_mut_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                ffi::RSA_PKCS1_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    /// Verify counterpart to `sign_pkcs1_raw`. `RSA_verify_raw` with
    /// `RSA_PKCS1_PADDING` performs the public-key operation, checks the
    /// PKCS#1 v1.5 padding, and returns the remainder (the caller is
    /// responsible for checking that remainder against the expected
    /// message, per AWS-LC's doc comment) -- so this compares the recovered
    /// bytes against `message` itself before reporting success.
    pub fn verify_pkcs1_raw(
        &self,
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let mut out = vec![0u8; self.key_size_bytes()];
        let mut out_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_verify_raw(
                self.rsa,
                &mut out_len,
                out.as_mut_ptr(),
                out.len(),
                sig.as_ptr(),
                sig.len(),
                ffi::RSA_PKCS1_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        out.truncate(out_len);
        if out.as_slice() != message {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(())
    }

    /// RSA-PSS sign. `hash_nid` (e.g. `ffi::NID_sha256`) identifies both the
    /// digest algorithm that produced `digest` and the MGF1 hash (AWS-LC's
    /// `RSA_sign_pss_mgf1` takes `mgf1_md = NULL` to mean "same as `md`",
    /// which is the common configuration). `salt_len = -1` means "use the
    /// digest's own output length as the salt length".
    /// `mgf1_hash_nid` is independent of `hash_nid` (the message digest):
    /// PKCS#11's `CK_RSA_PKCS_PSS_PARAMS` carries `hashAlg`/`mgf` as
    /// separate fields, and `RSA_sign_pss_mgf1`'s own `mgf1_md` parameter
    /// supports them differing genuinely -- passing `nid_to_evp_md(
    /// mgf1_hash_nid)` here rather than a hardcoded `std::ptr::null()`
    /// ("same as digest") is what makes that actually possible.
    pub fn sign_pss(
        &self,
        hash_nid: i32,
        mgf1_hash_nid: i32,
        digest: &[u8],
        salt_len: i32,
    ) -> Result<Vec<u8>, Error> {
        let md = nid_to_evp_md(hash_nid)?;
        let mgf1_md = nid_to_evp_md(mgf1_hash_nid)?;
        let mut sig = vec![0u8; self.key_size_bytes()];
        let mut sig_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_sign_pss_mgf1(
                self.rsa,
                &mut sig_len,
                sig.as_mut_ptr(),
                sig.len(),
                digest.as_ptr(),
                digest.len(),
                md,
                mgf1_md,
                salt_len,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    /// See `sign_pss`'s doc comment: `mgf1_hash_nid` is independent of
    /// `hash_nid`.
    pub fn verify_pss(
        &self,
        hash_nid: i32,
        mgf1_hash_nid: i32,
        digest: &[u8],
        salt_len: i32,
        sig: &[u8],
    ) -> Result<(), Error> {
        let md = nid_to_evp_md(hash_nid)?;
        let mgf1_md = nid_to_evp_md(mgf1_hash_nid)?;
        let ret = unsafe {
            ffi::RSA_verify_pss_mgf1(
                self.rsa,
                digest.as_ptr(),
                digest.len(),
                md,
                mgf1_md,
                salt_len,
                sig.as_ptr(),
                sig.len(),
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::VerifyFailed));
        }
        Ok(())
    }

    /// RSAES-OAEP encrypt. `RSA_encrypt`/`RSA_decrypt` with
    /// `RSA_PKCS1_OAEP_PADDING` fix both the OAEP hash and the MGF1 hash to
    /// SHA-1 (the classic RFC 8017 default) -- there is no parameter here to
    /// choose a different hash. That fixed-SHA-1 configuration is *not*
    /// sufficient for PKCS#11's `CK_RSA_PKCS_OAEP_PARAMS` (which allows an
    /// arbitrary hash/MGF1 pair): see `encrypt_oaep_mgf1`/`decrypt_oaep_mgf1`
    /// below for the general case. AWS-LC has no public
    /// `RSA_padding_check_PKCS1_OAEP*` unpad primitive, so a lower-level
    /// pad-then-raw-transform approach (`RSA_padding_add_PKCS1_OAEP_mgf1`
    /// plus `RSA_NO_PADDING`) isn't viable for decrypt either -- see
    /// `encrypt_oaep_mgf1`'s doc comment for the full explanation of why
    /// `EVP_PKEY_CTX` is used there instead. This pair is kept here for API
    /// completeness / as the simpler primitive when SHA-1 genuinely is all
    /// that's needed, but is unused by the current kryoptic integration
    /// layer (`src/awslc/rsa.rs` uses `encrypt_oaep_mgf1`/
    /// `decrypt_oaep_mgf1` exclusively).
    pub fn encrypt_oaep(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ct = vec![0u8; self.key_size_bytes()];
        let mut ct_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_encrypt(
                self.rsa,
                &mut ct_len,
                ct.as_mut_ptr(),
                ct.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ffi::RSA_PKCS1_OAEP_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        ct.truncate(ct_len);
        Ok(ct)
    }

    /// RSAES-OAEP decrypt. See `encrypt_oaep` re: the fixed-SHA-1 OAEP/MGF1
    /// configuration and why this pair is unused by the current integration
    /// layer.
    pub fn decrypt_oaep(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut pt = vec![0u8; self.key_size_bytes()];
        let mut pt_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_decrypt(
                self.rsa,
                &mut pt_len,
                pt.as_mut_ptr(),
                pt.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                ffi::RSA_PKCS1_OAEP_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        pt.truncate(pt_len);
        Ok(pt)
    }

    /// RSAES-OAEP encrypt with a caller-selected OAEP digest, MGF1 digest,
    /// and optional label -- the general form PKCS#11's
    /// `CK_RSA_PKCS_OAEP_PARAMS` needs.
    ///
    /// ## Why this exists alongside `encrypt_oaep`/`decrypt_oaep` above
    ///
    /// `encrypt_oaep`/`decrypt_oaep` above are fixed to AWS-LC's classic
    /// `RSA_encrypt`/`RSA_decrypt` SHA-1/SHA-1 OAEP configuration, with no
    /// parameter to choose a different hash or supply a non-empty label.
    /// That is *not* sufficient for this codebase's own test suite:
    /// `src/tests/rsa.rs` drives `CK_RSA_PKCS_OAEP_PARAMS.hashAlg`/`mgf`
    /// through `CKM_SHA224`/`CKG_MGF1_SHA224`,
    /// `CKM_SHA256`/`CKG_MGF1_SHA256`, `CKM_SHA384`/`CKG_MGF1_SHA384`, and
    /// `CKM_SHA512`/`CKG_MGF1_SHA512` (see `test_rsa_operations`'s "RSA
    /// PKCS OAEP Enc"/wrap-key sections and `test_rsa_sign_verify`'s
    /// `for hash in [...]` loop over all four) -- never SHA-1 alone. So
    /// `RsaKey`'s public API needs a configurable-hash OAEP path, and
    /// `src/awslc/rsa.rs` (this crate's kryoptic integration layer) uses
    /// this one, not the fixed-SHA-1 pair above.
    ///
    /// ## Why `EVP_PKEY_CTX`, not `RSA_padding_add_PKCS1_OAEP_mgf1` +
    /// a raw transform
    ///
    /// AWS-LC's public `rsa.h` exposes `RSA_padding_add_PKCS1_OAEP_mgf1`
    /// (pads a message, ready for a raw private/public-key transform) but,
    /// confirmed against both the vendored `aws-lc/include/openssl/rsa.h`
    /// header and `aws-lc-sys` 0.34's generated bindings (grepped for every
    /// `RSA_padding_check*`/`*OAEP*` symbol), there is **no** matching
    /// "check"/unpad primitive exposed for the decrypt direction -- only
    /// the encrypt-direction `RSA_padding_add_PKCS1_OAEP[_mgf1]` pair
    /// exists publicly. So composing `RSA_padding_add_PKCS1_OAEP_mgf1`
    /// with `raw_transform_public` would work for
    /// `encrypt_oaep_mgf1`, but `decrypt_oaep_mgf1` would have no AWS-LC
    /// primitive at all to verify/undo the OAEP padding after
    /// `raw_transform_private` -- hand-rolling that unpadding step
    /// ourselves (a security-critical, constant-time-sensitive routine)
    /// would be exactly the kind of "wrong implementation to make a test
    /// pass" mistake to avoid.
    ///
    /// AWS-LC's `EVP_PKEY_CTX` layer, by contrast, supports
    /// configurable-hash OAEP symmetrically on *both* directions:
    /// `EVP_PKEY_encrypt`/`EVP_PKEY_decrypt` plus
    /// `EVP_PKEY_CTX_set_rsa_padding`/`set_rsa_oaep_md`/`set_rsa_mgf1_md`/
    /// `set0_rsa_oaep_label` -- all confirmed present in `aws-lc-sys`
    /// 0.34's bindings (`evp.h`/the generated `*_crypto.rs`) -- so this
    /// method (and `decrypt_oaep_mgf1` below) use that instead.
    ///
    /// `md_nid`/`mgf1_nid` are independent AWS-LC NIDs (e.g. `NID_sha256`),
    /// matching `CK_RSA_PKCS_OAEP_PARAMS`'s independent `hashAlg`/`mgf`
    /// fields exactly. This is *not* the same situation as `sign_pss`/
    /// `verify_pss` above collapsing both hashes into one `hash_nid`
    /// parameter: that collapse was forced by `RSA_sign_pss_mgf1`'s
    /// `mgf1md = NULL` convention (AWS-LC's PSS primitive only exposes a
    /// single hash). `EVP_PKEY_CTX_set_rsa_oaep_md`/`set_rsa_mgf1_md` are
    /// two genuinely independent setters here, so there is no primitive-
    /// level reason to force them through one parameter.
    ///
    /// `label`, when `Some` and non-empty, is the OAEP label (RFC 8017's
    /// `L`, PKCS#11's `pSourceData`). `None` (or `Some(&[])`) leaves
    /// AWS-LC's default label in place, which is the empty octet string --
    /// RFC 8017's default, and (per the same grep above) the only value
    /// this codebase's test suite ever exercises for `pSourceData`.
    pub fn encrypt_oaep_mgf1(
        &self,
        plaintext: &[u8],
        md_nid: i32,
        mgf1_nid: i32,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let ctx = OaepPkeyCtx::new(
            self.rsa,
            md_nid,
            mgf1_nid,
            label,
            ffi::EVP_PKEY_encrypt_init,
        )?;
        ctx.transform(plaintext, ffi::EVP_PKEY_encrypt)
    }

    /// RSAES-OAEP decrypt counterpart to `encrypt_oaep_mgf1`. See that
    /// method's doc comment for why this uses `EVP_PKEY_CTX`/
    /// `EVP_PKEY_decrypt` rather than a lower-level padding-check
    /// primitive (AWS-LC does not publicly expose one for OAEP).
    pub fn decrypt_oaep_mgf1(
        &self,
        ciphertext: &[u8],
        md_nid: i32,
        mgf1_nid: i32,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let ctx = OaepPkeyCtx::new(
            self.rsa,
            md_nid,
            mgf1_nid,
            label,
            ffi::EVP_PKEY_decrypt_init,
        )?;
        ctx.transform(ciphertext, ffi::EVP_PKEY_decrypt)
    }

    /// RSAES-PKCS1-v1_5 encrypt (RFC 2313/8017 "block type 2" padding).
    ///
    /// `CKM_RSA_PKCS` needs both a
    /// `Sign`/`Verify` framing (`sign_pkcs1`/`sign_pkcs1_raw` above) and a
    /// separate `Encryption`/`Decryption` framing, which is what this and
    /// `decrypt_pkcs1` provide. Built the same way `encrypt_oaep` is, just
    /// with `RSA_PKCS1_PADDING` instead of `RSA_PKCS1_OAEP_PADDING`.
    pub fn encrypt_pkcs1(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ct = vec![0u8; self.key_size_bytes()];
        let mut ct_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_encrypt(
                self.rsa,
                &mut ct_len,
                ct.as_mut_ptr(),
                ct.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ffi::RSA_PKCS1_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        ct.truncate(ct_len);
        Ok(ct)
    }

    /// RSAES-PKCS1-v1_5 decrypt. See `encrypt_pkcs1` re: this pair's scope.
    pub fn decrypt_pkcs1(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // `pt` can hold the raw (unpadded) private-key-transform output
        // even if the subsequent padding check fails -- a `SecretBuf`
        // (rather than a plain `Vec<u8>`) scrubs it automatically on that
        // path, matching this crate's convention for sensitive buffers.
        let mut pt = SecretBuf::zeroed(self.key_size_bytes());
        let mut pt_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_decrypt(
                self.rsa,
                &mut pt_len,
                pt.as_mut_ptr(),
                pt.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                ffi::RSA_PKCS1_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        pt.truncate(pt_len);
        Ok(pt.into_vec())
    }

    /// Raw/unpadded RSA private-key transform (`m^d mod n`), for PKCS#11's
    /// `CKM_RSA_X_509` mechanism. Named by which key half performs the
    /// operation (private), not by which PKCS#11 operation framing
    /// (sign/decrypt) invokes it -- both framings use the same raw modular
    /// exponentiation.
    ///
    /// `RSA_sign_raw` with `RSA_NO_PADDING` was empirically verified (see
    /// `raw_transform_rejects_wrong_length_input`) to itself reject input
    /// shorter than `key_size_bytes()`, matching the OpenSSL reference
    /// backend's behavior for `CKM_RSA_X_509` (which likewise relies on the
    /// underlying no-padding primitive's exact-length requirement rather
    /// than an explicit length check of its own).
    pub fn raw_transform_private(
        &self,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Same reasoning as `decrypt_pkcs1` above: `out` holds the raw
        // private-key-transform output even on failure, so it's a
        // `SecretBuf` to scrub it automatically on that path.
        let mut out = SecretBuf::zeroed(self.key_size_bytes());
        let mut out_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_sign_raw(
                self.rsa,
                &mut out_len,
                out.as_mut_ptr(),
                out.len(),
                input.as_ptr(),
                input.len(),
                ffi::RSA_NO_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        out.truncate(out_len);
        Ok(out.into_vec())
    }

    /// Raw/unpadded RSA public-key transform (`m^e mod n`), for PKCS#11's
    /// `CKM_RSA_X_509` mechanism. Named by which key half performs the
    /// operation (public), not by which PKCS#11 operation framing
    /// (verify/encrypt) invokes it. See `raw_transform_private` re: input
    /// length enforcement.
    pub fn raw_transform_public(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.key_size_bytes()];
        let mut out_len: usize = 0;
        let ret = unsafe {
            ffi::RSA_verify_raw(
                self.rsa,
                &mut out_len,
                out.as_mut_ptr(),
                out.len(),
                input.as_ptr(),
                input.len(),
                ffi::RSA_NO_PADDING,
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        out.truncate(out_len);
        Ok(out)
    }
}

/// RAII wrapper around the `EVP_PKEY`/`EVP_PKEY_CTX` pair
/// `encrypt_oaep_mgf1`/`decrypt_oaep_mgf1` share, configured for OAEP with
/// a caller-chosen digest/MGF1 digest/label. See `encrypt_oaep_mgf1`'s doc
/// comment for why this `EVP_PKEY_CTX`-based approach exists.
///
/// `EVP_PKEY_set1_RSA` (the `set1`, not `assign`, variant) up-refs `rsa`
/// rather than taking ownership of it -- confirmed against AWS-LC's
/// `evp.h` doc comment for the `set1`/`get1` naming convention ("return a
/// fresh reference to the underlying object") -- so this never takes `rsa`
/// out of the `RsaKey` that owns it; `self.rsa` stays valid and is freed
/// exactly once, by `RsaKey::drop`, regardless of this struct's lifetime.
struct OaepPkeyCtx {
    pkey: *mut ffi::EVP_PKEY,
    ctx: *mut ffi::EVP_PKEY_CTX,
}

impl OaepPkeyCtx {
    /// Builds and configures the context: OAEP padding, `md_nid`'s digest,
    /// `mgf1_nid`'s MGF1 digest, and (if `label` is `Some` and non-empty)
    /// the OAEP label.
    fn new(
        rsa: *mut ffi::RSA,
        md_nid: i32,
        mgf1_nid: i32,
        label: Option<&[u8]>,
        init_fn: unsafe extern "C" fn(
            *mut ffi::EVP_PKEY_CTX,
        ) -> std::os::raw::c_int,
    ) -> Result<OaepPkeyCtx, Error> {
        let md = nid_to_evp_md(md_nid)?;
        let mgf1_md = nid_to_evp_md(mgf1_nid)?;

        let pkey = unsafe { ffi::EVP_PKEY_new() };
        if pkey.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        if unsafe { ffi::EVP_PKEY_set1_RSA(pkey, rsa) } != 1 {
            unsafe { ffi::EVP_PKEY_free(pkey) };
            return Err(Error::new(ErrorKind::BackendError));
        }

        let ctx = unsafe { ffi::EVP_PKEY_CTX_new(pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            unsafe { ffi::EVP_PKEY_free(pkey) };
            return Err(Error::new(ErrorKind::NullPtr));
        }

        // `EVP_PKEY_encrypt_init`/`decrypt_init` must run *before* the
        // `EVP_PKEY_CTX_set_rsa_*` control calls below: AWS-LC's (and
        // OpenSSL's) `EVP_PKEY_CTX` control-operation dispatch is keyed off
        // `ctx->operation`, which `_init` sets -- calling the setters first
        // (against a freshly-created, not-yet-initialized context) was
        // empirically observed to report success (return 1) while silently
        // having no effect, leaving the context on its PKCS#1 v1.5 default
        // padding instead of OAEP and producing ciphertext neither
        // `encrypt_oaep_mgf1` nor `decrypt_oaep_mgf1` could round-trip --
        // caught by this file's own `oaep_mgf1_*` tests below before this
        // ordering fix.
        if unsafe { init_fn(ctx) } != 1 {
            unsafe {
                ffi::EVP_PKEY_CTX_free(ctx);
                ffi::EVP_PKEY_free(pkey);
            }
            return Err(Error::new(ErrorKind::BackendError));
        }

        let setup_ok = unsafe {
            ffi::EVP_PKEY_CTX_set_rsa_padding(ctx, ffi::RSA_PKCS1_OAEP_PADDING)
                == 1
                && ffi::EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) == 1
                && ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) == 1
        };
        if !setup_ok {
            unsafe {
                ffi::EVP_PKEY_CTX_free(ctx);
                ffi::EVP_PKEY_free(pkey);
            }
            return Err(Error::new(ErrorKind::BackendError));
        }

        if let Some(l) = label {
            if !l.is_empty() {
                // EVP_PKEY_CTX_set0_rsa_oaep_label DANGER (per its doc
                // comment): "On success, this call takes ownership of
                // |label| and will call |OPENSSL_free| on it when |ctx| is
                // destroyed" -- so this buffer must be OPENSSL_malloc'd
                // (not a Rust Vec/Box, which OPENSSL_free must not be
                // called on), and freed by us instead if the call fails
                // (ownership only transfers on success).
                let buf = unsafe { ffi::OPENSSL_malloc(l.len()) } as *mut u8;
                if buf.is_null() {
                    unsafe {
                        ffi::EVP_PKEY_CTX_free(ctx);
                        ffi::EVP_PKEY_free(pkey);
                    }
                    return Err(Error::new(ErrorKind::NullPtr));
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(l.as_ptr(), buf, l.len())
                };
                let label_ok = unsafe {
                    ffi::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, buf, l.len())
                        == 1
                };
                if !label_ok {
                    unsafe {
                        ffi::OPENSSL_free(buf as *mut std::ffi::c_void);
                        ffi::EVP_PKEY_CTX_free(ctx);
                        ffi::EVP_PKEY_free(pkey);
                    }
                    return Err(Error::new(ErrorKind::BackendError));
                }
            }
        }

        Ok(OaepPkeyCtx { pkey, ctx })
    }

    /// Runs `op` (either `EVP_PKEY_encrypt` or `EVP_PKEY_decrypt`, both of
    /// which share this exact signature) over `input` using this context's
    /// configuration, first probing the required output length with a
    /// `NULL` output buffer (per both functions' documented two-pass
    /// convention) and then filling a correctly-sized buffer.
    fn transform(
        &self,
        input: &[u8],
        op: unsafe extern "C" fn(
            *mut ffi::EVP_PKEY_CTX,
            *mut u8,
            *mut usize,
            *const u8,
            usize,
        ) -> std::os::raw::c_int,
    ) -> Result<Vec<u8>, Error> {
        let mut out_len: usize = 0;
        let ret = unsafe {
            op(
                self.ctx,
                std::ptr::null_mut(),
                &mut out_len,
                input.as_ptr(),
                input.len(),
            )
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }

        let mut out = vec![0u8; out_len];
        let mut final_len = out_len;
        let ret = unsafe {
            op(
                self.ctx,
                out.as_mut_ptr(),
                &mut final_len,
                input.as_ptr(),
                input.len(),
            )
        };
        if ret != 1 {
            zeromem(out.as_mut_slice());
            return Err(Error::new(ErrorKind::BackendError));
        }
        out.truncate(final_len);
        Ok(out)
    }
}

impl Drop for OaepPkeyCtx {
    fn drop(&mut self) {
        // EVP_PKEY_CTX_free also frees the OAEP label buffer this struct
        // may have OPENSSL_malloc'd and handed to
        // EVP_PKEY_CTX_set0_rsa_oaep_label above (that call's ownership
        // transfer). EVP_PKEY_free only drops this wrapper's own reference
        // to the RSA key (EVP_PKEY_set1_RSA up-refs, per `OaepPkeyCtx`'s
        // doc comment) -- the `RsaKey` that lent us `rsa` still owns and
        // frees it separately.
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.ctx);
            ffi::EVP_PKEY_free(self.pkey);
        }
    }
}

/// Maps a hash NID to its `EVP_MD` singleton, for use with
/// `RSA_sign_pss_mgf1`/`RSA_verify_pss_mgf1`, which take `*const EVP_MD`
/// rather than a NID directly.
///
/// `awslc::digest::DigestAlg` maps an enum (not a NID) to `EVP_MD`, so it
/// isn't directly reusable here without a NID<->DigestAlg translation layer
/// that would add more indirection than it saves; this local lookup mirrors
/// the hash set PKCS#11's `CKM_RSA_PKCS_PSS` mechanism actually exercises
/// (SHA-1/224/256/384/512), matching `sign_pkcs1`/`verify_pkcs1` above,
/// which already take a raw NID in this file's existing style.
/// Maps `crate::digest::DigestAlg` to the AWS-LC NID `sign_pkcs1`/
/// `verify_pkcs1` (and, in the future, `sign_pss`/`verify_pss`) take as
/// their `hash_nid` parameter.
///
/// Added for kryoptic's integration layer (`src/awslc/rsa.rs`): that layer
/// only depends on this crate's public API, never `aws_lc_sys` directly, so
/// it has no other way to turn a `DigestAlg` (which is what
/// `crate::awslc::common::mech_type_to_digest_alg` -- the shared
/// mechanism-to-hash mapping every backend module here uses -- returns) into
/// the NID these signing primitives need.
pub fn digest_alg_to_nid(alg: crate::digest::DigestAlg) -> i32 {
    use crate::digest::DigestAlg::*;
    match alg {
        Sha1 => ffi::NID_sha1,
        Sha2_224 => ffi::NID_sha224,
        Sha2_256 => ffi::NID_sha256,
        Sha2_384 => ffi::NID_sha384,
        Sha2_512 => ffi::NID_sha512,
        Sha2_512_224 => ffi::NID_sha512_224,
        Sha2_512_256 => ffi::NID_sha512_256,
        Sha3_224 => ffi::NID_sha3_224,
        Sha3_256 => ffi::NID_sha3_256,
        Sha3_384 => ffi::NID_sha3_384,
        Sha3_512 => ffi::NID_sha3_512,
    }
}

/// Narrow addition to support `src/awslc/rsa.rs`'s PSS wiring:
/// SHA3 support. `src/rsa.rs::register` unconditionally registers
/// `CKM_SHA3_{224,256,384,512}_RSA_PKCS_PSS` (no feature gate, unlike
/// `CKM_SHA1_*`'s `no_sha1`), and those mechanisms reach `sign_pss`/
/// `verify_pss` above -- so without this, a caller using one of those
/// mechanisms would hit `ErrorKind::WrapperError` even though the
/// mechanism is registered and otherwise functional (its non-PSS sibling,
/// `CKM_SHA3_256_RSA_PKCS` etc., already works via `sign_pkcs1`/
/// `verify_pkcs1`, which take a NID directly and don't need this
/// EVP_MD lookup). `EVP_sha3_{224,256,384,512}` are confirmed present in
/// `aws_lc_sys` (checked against the vendored bindings).
fn nid_to_evp_md(hash_nid: i32) -> Result<*const ffi::EVP_MD, Error> {
    let md = unsafe {
        match hash_nid {
            ffi::NID_sha1 => ffi::EVP_sha1(),
            ffi::NID_sha224 => ffi::EVP_sha224(),
            ffi::NID_sha256 => ffi::EVP_sha256(),
            ffi::NID_sha384 => ffi::EVP_sha384(),
            ffi::NID_sha512 => ffi::EVP_sha512(),
            ffi::NID_sha512_224 => ffi::EVP_sha512_224(),
            ffi::NID_sha512_256 => ffi::EVP_sha512_256(),
            ffi::NID_sha3_224 => ffi::EVP_sha3_224(),
            ffi::NID_sha3_256 => ffi::EVP_sha3_256(),
            ffi::NID_sha3_384 => ffi::EVP_sha3_384(),
            ffi::NID_sha3_512 => ffi::EVP_sha3_512(),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        }
    };
    Ok(md)
}

fn bin_to_bn(bytes: &[u8]) -> Result<*mut ffi::BIGNUM, Error> {
    let bn = unsafe {
        ffi::BN_bin2bn(bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
    };
    if bn.is_null() {
        return Err(Error::new(ErrorKind::NullPtr));
    }
    Ok(bn)
}

fn bn_to_vec(bn: *const ffi::BIGNUM) -> Vec<u8> {
    let len = unsafe { ffi::BN_num_bytes(bn) } as usize;
    let mut buf = vec![0u8; len];
    unsafe { ffi::BN_bn2bin(bn, buf.as_mut_ptr()) };
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_2048_round_trip_sizes() {
        let key = RsaKey::generate(2048).unwrap();
        assert_eq!(key.key_size_bytes(), 256);
        assert_eq!(key.modulus().len(), 256);
        assert!(!key.public_exponent().is_empty());
        assert!(!key.private_exponent().is_empty());
        assert!(!key.prime1().is_empty());
        assert!(!key.prime2().is_empty());
        assert!(!key.exponent1().is_empty());
        assert!(!key.exponent2().is_empty());
        assert!(!key.coefficient().is_empty());
    }

    #[test]
    fn pkcs1_sign_verify_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        assert_eq!(sig.len(), 256);
        key.verify_pkcs1(ffi::NID_sha256, &digest, &sig).unwrap();
    }

    #[test]
    fn pkcs1_verify_rejects_tampered_digest() {
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        let mut bad_digest = digest;
        bad_digest[0] ^= 0xff;
        assert!(key
            .verify_pkcs1(ffi::NID_sha256, &bad_digest, &sig)
            .is_err());
    }

    #[test]
    fn from_public_components_can_verify_but_not_sign_material() {
        let key = RsaKey::generate(2048).unwrap();
        let n = key.modulus();
        let e = key.public_exponent();
        let pubkey = RsaKey::from_public_components(&n, &e).unwrap();
        let digest = [0x42u8; 32];
        let sig = key.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        pubkey.verify_pkcs1(ffi::NID_sha256, &digest, &sig).unwrap();
    }

    #[test]
    fn from_private_components_full_crt_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        let reconstructed = RsaKey::from_private_components(
            &key.modulus(),
            &key.public_exponent(),
            &key.private_exponent(),
            Some((
                &key.prime1(),
                &key.prime2(),
                &key.exponent1(),
                &key.exponent2(),
                &key.coefficient(),
            )),
        )
        .unwrap();
        let digest = [0x42u8; 32];
        let sig = reconstructed.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        key.verify_pkcs1(ffi::NID_sha256, &digest, &sig).unwrap();
    }

    #[test]
    fn pss_sign_verify_default_salt_len() {
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        // salt_len = -1: AWS-LC's convention for "use the digest's own
        // output length as the salt length" (the common configuration).
        let sig = key
            .sign_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, -1)
            .unwrap();
        key.verify_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, -1, &sig)
            .unwrap();
    }

    #[test]
    fn pss_sign_verify_explicit_salt_len() {
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key
            .sign_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, 32)
            .unwrap();
        key.verify_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, 32, &sig)
            .unwrap();
    }

    #[test]
    fn pss_verify_rejects_tampered_digest() {
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key
            .sign_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, -1)
            .unwrap();
        let mut bad = digest;
        bad[0] ^= 0xff;
        assert!(key
            .verify_pss(ffi::NID_sha256, ffi::NID_sha256, &bad, -1, &sig)
            .is_err());
    }

    #[test]
    fn pss_verify_rejects_wrong_salt_len_mismatch() {
        // A signature made with an explicit salt_len must not verify
        // against a different expected salt_len.
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key
            .sign_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, 32)
            .unwrap();
        assert!(key
            .verify_pss(ffi::NID_sha256, ffi::NID_sha256, &digest, 16, &sig)
            .is_err());
    }

    #[test]
    fn pss_sign_verify_sha3_256() {
        // AWS-LC's classic RSA_sign/RSA_verify take a NID directly and
        // don't need an EVP_MD lookup, but RSA_sign_pss_mgf1/
        // RSA_verify_pss_mgf1 do (they take `*const EVP_MD`) -- this
        // exercises `nid_to_evp_md`'s SHA3 support, added alongside
        // kryoptic's integration layer (`src/awslc/rsa.rs`) because
        // `src/rsa.rs::register` unconditionally registers
        // CKM_SHA3_*_RSA_PKCS_PSS mechanisms that reach this code path.
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let sig = key
            .sign_pss(ffi::NID_sha3_256, ffi::NID_sha3_256, &digest, -1)
            .unwrap();
        key.verify_pss(ffi::NID_sha3_256, ffi::NID_sha3_256, &digest, -1, &sig)
            .unwrap();
    }

    #[test]
    fn oaep_encrypt_decrypt_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello OAEP";
        let ct = key.encrypt_oaep(pt).unwrap();
        assert_eq!(ct.len(), 256);
        let pt2 = key.decrypt_oaep(&ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn oaep_decrypt_rejects_tampered_ciphertext() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello OAEP";
        let mut ct = key.encrypt_oaep(pt).unwrap();
        ct[0] ^= 0xff;
        assert!(key.decrypt_oaep(&ct).is_err());
    }

    #[test]
    fn oaep_encrypt_rejects_message_too_long_for_key_size() {
        let key = RsaKey::generate(2048).unwrap();
        // 2048-bit key with SHA-1 OAEP: max message length is
        // key_size_bytes - 2*hash_len - 2 = 256 - 40 - 2 = 214 bytes.
        let too_long = vec![0x41u8; 215];
        assert!(key.encrypt_oaep(&too_long).is_err());
    }

    #[test]
    fn oaep_mgf1_encrypt_decrypt_round_trip_sha256() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello configurable OAEP";
        let ct = key
            .encrypt_oaep_mgf1(pt, ffi::NID_sha256, ffi::NID_sha256, None)
            .unwrap();
        assert_eq!(ct.len(), 256);
        let pt2 = key
            .decrypt_oaep_mgf1(&ct, ffi::NID_sha256, ffi::NID_sha256, None)
            .unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn oaep_mgf1_encrypt_decrypt_round_trip_sha512() {
        // Matches src/tests/rsa.rs's "oaep-sha512-sha512.txt" vector shape
        // (hashAlg=CKM_SHA512, mgf=CKG_MGF1_SHA512) -- this codebase's own
        // reference test suite never exercises OAEP with SHA-1 alone.
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello sha512 OAEP";
        let ct = key
            .encrypt_oaep_mgf1(pt, ffi::NID_sha512, ffi::NID_sha512, None)
            .unwrap();
        assert_eq!(ct.len(), 256);
        let pt2 = key
            .decrypt_oaep_mgf1(&ct, ffi::NID_sha512, ffi::NID_sha512, None)
            .unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn oaep_mgf1_encrypt_decrypt_round_trip_with_label() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello labeled OAEP";
        let label = b"a non-empty OAEP label";
        let ct = key
            .encrypt_oaep_mgf1(
                pt,
                ffi::NID_sha256,
                ffi::NID_sha256,
                Some(label),
            )
            .unwrap();
        let pt2 = key
            .decrypt_oaep_mgf1(
                &ct,
                ffi::NID_sha256,
                ffi::NID_sha256,
                Some(label),
            )
            .unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn oaep_mgf1_decrypt_rejects_wrong_label() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello labeled OAEP";
        let ct = key
            .encrypt_oaep_mgf1(
                pt,
                ffi::NID_sha256,
                ffi::NID_sha256,
                Some(b"label A"),
            )
            .unwrap();
        assert!(key
            .decrypt_oaep_mgf1(
                &ct,
                ffi::NID_sha256,
                ffi::NID_sha256,
                Some(b"label B"),
            )
            .is_err());
    }

    #[test]
    fn oaep_mgf1_decrypt_rejects_tampered_ciphertext() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello configurable OAEP";
        let mut ct = key
            .encrypt_oaep_mgf1(pt, ffi::NID_sha256, ffi::NID_sha256, None)
            .unwrap();
        ct[0] ^= 0xff;
        assert!(key
            .decrypt_oaep_mgf1(&ct, ffi::NID_sha256, ffi::NID_sha256, None)
            .is_err());
    }

    #[test]
    fn oaep_mgf1_encrypt_rejects_message_too_long_for_key_size() {
        let key = RsaKey::generate(2048).unwrap();
        // 2048-bit key with SHA-256 OAEP: max message length is
        // key_size_bytes - 2*hash_len - 2 = 256 - 64 - 2 = 190 bytes.
        let too_long = vec![0x41u8; 191];
        assert!(key
            .encrypt_oaep_mgf1(
                &too_long,
                ffi::NID_sha256,
                ffi::NID_sha256,
                None
            )
            .is_err());
    }

    #[test]
    fn oaep_mgf1_encrypt_rejects_unsupported_digest_nid() {
        let key = RsaKey::generate(2048).unwrap();
        // NID_md5 (or any NID nid_to_evp_md doesn't map) must be rejected
        // cleanly, not passed through to AWS-LC as a null EVP_MD pointer.
        let pt = b"hello";
        assert!(key
            .encrypt_oaep_mgf1(pt, ffi::NID_md5, ffi::NID_sha256, None)
            .is_err());
    }

    #[test]
    fn raw_round_trip_private_then_public() {
        let key = RsaKey::generate(2048).unwrap();
        let mut input = vec![0u8; key.key_size_bytes()];
        input[key.key_size_bytes() - 1] = 0x2a;
        let transformed = key.raw_transform_private(&input).unwrap();
        let recovered = key.raw_transform_public(&transformed).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn raw_round_trip_public_then_private() {
        let key = RsaKey::generate(2048).unwrap();
        let mut input = vec![0u8; key.key_size_bytes()];
        input[key.key_size_bytes() - 1] = 0x2a;
        let transformed = key.raw_transform_public(&input).unwrap();
        let recovered = key.raw_transform_private(&transformed).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn raw_transform_rejects_wrong_length_input() {
        let key = RsaKey::generate(2048).unwrap();
        let too_short = vec![0x2au8; key.key_size_bytes() - 1];
        assert!(key.raw_transform_private(&too_short).is_err());
    }

    #[test]
    fn from_private_components_no_crt_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        // No CRT parameters supplied -- PKCS#11 makes them optional.
        let reconstructed = RsaKey::from_private_components(
            &key.modulus(),
            &key.public_exponent(),
            &key.private_exponent(),
            None,
        )
        .unwrap();
        let digest = [0x42u8; 32];
        let sig = reconstructed.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        key.verify_pkcs1(ffi::NID_sha256, &digest, &sig).unwrap();
    }

    #[test]
    fn generate_with_exponent_honors_custom_exponent() {
        // A small, valid odd exponent other than F4 (65537), to confirm
        // the caller's requested exponent is actually the one AWS-LC
        // generates with, not silently ignored in favor of F4.
        let key = RsaKey::generate_with_exponent(2048, &[0x11]).unwrap(); // e = 17
        assert_eq!(key.public_exponent(), vec![0x11]);
        let digest = [0x42u8; 32];
        let sig = key.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        key.verify_pkcs1(ffi::NID_sha256, &digest, &sig).unwrap();
    }

    #[test]
    fn generate_default_still_uses_f4() {
        let key = RsaKey::generate(2048).unwrap();
        assert_eq!(key.public_exponent(), vec![0x01, 0x00, 0x01]);
    }

    #[test]
    fn pkcs1_raw_sign_verify_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        let message = b"a short DigestInfo-shaped message";
        let sig = key.sign_pkcs1_raw(message).unwrap();
        assert_eq!(sig.len(), 256);
        key.verify_pkcs1_raw(message, &sig).unwrap();
    }

    #[test]
    fn pkcs1_raw_verify_rejects_tampered_message() {
        let key = RsaKey::generate(2048).unwrap();
        let message = b"a short DigestInfo-shaped message";
        let sig = key.sign_pkcs1_raw(message).unwrap();
        assert!(key
            .verify_pkcs1_raw(b"a different message!!", &sig)
            .is_err());
    }

    #[test]
    fn pkcs1_raw_verify_rejects_tampered_signature() {
        let key = RsaKey::generate(2048).unwrap();
        let message = b"a short DigestInfo-shaped message";
        let mut sig = key.sign_pkcs1_raw(message).unwrap();
        sig[0] ^= 0xff;
        assert!(key.verify_pkcs1_raw(message, &sig).is_err());
    }

    #[test]
    fn pkcs1_raw_sign_differs_from_digestinfo_sign() {
        // sign_pkcs1_raw (no DigestInfo) and sign_pkcs1 (DigestInfo-wrapped)
        // are genuinely different constructions over the same bytes -- a
        // signature from one must not verify with the other.
        let key = RsaKey::generate(2048).unwrap();
        let digest = [0x42u8; 32];
        let digestinfo_sig = key.sign_pkcs1(ffi::NID_sha256, &digest).unwrap();
        assert!(key.verify_pkcs1_raw(&digest, &digestinfo_sig).is_err());

        let raw_sig = key.sign_pkcs1_raw(&digest).unwrap();
        assert!(key
            .verify_pkcs1(ffi::NID_sha256, &digest, &raw_sig)
            .is_err());
    }

    #[test]
    fn pkcs1_encrypt_decrypt_round_trip() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello PKCS1v1.5";
        let ct = key.encrypt_pkcs1(pt).unwrap();
        assert_eq!(ct.len(), 256);
        let pt2 = key.decrypt_pkcs1(&ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn pkcs1_decrypt_rejects_tampered_ciphertext() {
        let key = RsaKey::generate(2048).unwrap();
        let pt = b"hello PKCS1v1.5";
        let mut ct = key.encrypt_pkcs1(pt).unwrap();
        ct[0] ^= 0xff;
        assert!(key.decrypt_pkcs1(&ct).is_err());
    }

    #[test]
    fn pkcs1_encrypt_rejects_message_too_long_for_key_size() {
        let key = RsaKey::generate(2048).unwrap();
        // 2048-bit key with PKCS#1 v1.5 padding: max message length is
        // key_size_bytes - 11 = 256 - 11 = 245 bytes.
        let too_long = vec![0x41u8; 246];
        assert!(key.encrypt_pkcs1(&too_long).is_err());
    }

    #[test]
    fn digest_alg_to_nid_maps_expected_values() {
        use crate::digest::DigestAlg;
        assert_eq!(digest_alg_to_nid(DigestAlg::Sha1), ffi::NID_sha1);
        assert_eq!(digest_alg_to_nid(DigestAlg::Sha2_256), ffi::NID_sha256);
        assert_eq!(digest_alg_to_nid(DigestAlg::Sha2_384), ffi::NID_sha384);
        assert_eq!(digest_alg_to_nid(DigestAlg::Sha2_512), ffi::NID_sha512);
        assert_eq!(digest_alg_to_nid(DigestAlg::Sha3_256), ffi::NID_sha3_256);
    }
}
