// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the AES surface `src/aes.rs` requires:
//! `AesOperation`, `AesMacOperation`, `AesCmacOperation` (mirroring
//! `crate::ossl::aes`, which `src/aes.rs` imports via
//! `use crate::ossl::aes::*;`).
//!
//! The one-shot message-mode path (`AesOperation::msg_encrypt_init`/
//! `msg_decrypt_init` plus the `MsgEncryption::msg_encrypt`/
//! `MsgDecryption::msg_decrypt` one-shot methods) is real for both
//! `CKM_AES_GCM` and `CKM_AES_CCM` -- the only two mechanisms PKCS#11's
//! message-based encrypt/decrypt API is defined for in this codebase.
//! Message mode is deliberately NOT extended to the classic block-cipher
//! mechanisms (ECB, CBC, CBC-PAD, CTR, OFB, CFB1/8/128): PKCS#11's
//! message-based API has no defined per-message parameter struct for any
//! of them (`CK_GCM_MESSAGE_PARAMS`/`CK_CCM_MESSAGE_PARAMS` are the only
//! two that exist anywhere in this codebase's bindings), the reference
//! `src/ossl/aes.rs`'s own `impl MsgEncryption`/`impl MsgDecryption for
//! AesOperation` likewise only ever matches `CKM_AES_GCM`/`CKM_AES_CCM`
//! (falling through to `CKR_GENERAL_ERROR` otherwise), and the shared
//! `crate::aes::AES_MECHS` mechanism-info table this module's own
//! `register_mechanisms` reuses (`AES_MECHS[0]` for ECB/CBC/CBC-PAD/CTR,
//! `AES_MECHS[2]` for OFB/CFB1/8/128) grants those mechanisms no
//! `CKF_MESSAGE_ENCRYPT`/`CKF_MESSAGE_DECRYPT` flag at all -- so
//! `AesMechanism::msg_encryption_op`/`msg_decryption_op` (`src/aes.rs`)
//! already reject them with `CKR_MECHANISM_INVALID` before ever reaching
//! this module, for either backend. Classic (non-message) `Encryption`/
//! `Decryption` support for ECB, CBC, CBC-PAD, CTR, OFB, CFB1/8/128, GCM
//! and CCM via `encrypt_new`/`decrypt_new` -- the `C_EncryptInit`/
//! `C_Encrypt`/`C_EncryptUpdate` surface real PKCS#11 applications use --
//! is unaffected and remains real for all of them.
//! `CKM_AES_CTS` is a permanent gap (AWS-LC has no ciphertext-stealing
//! primitive) and always returns `CKR_MECHANISM_INVALID`. AES key-wrap
//! (`wrap`/`unwrap`, covering `CKM_AES_KEY_WRAP`/`_PKCS7`/`_KWP`) is real,
//! built directly on `awslc::cipher::AesKeyWrap` rather than through
//! `ClassicMode`/`encrypt_new` -- see `wrap`'s doc comment below for why.
//! A custom initial value (`mech.pParameter`) is not supported for any of
//! the three key-wrap mechanisms, since `awslc::cipher::AesKeyWrap` always
//! uses the RFC 3394/5649 default IV.
//!
//! Two known, deliberate limitations stemming from `awslc::cipher`'s
//! primitives (see each type's doc comment below for the reasoning):
//! - Classic CKM_AES_GCM buffers the *entire* message and only calls
//!   AWS-LC's one-shot `AesGcm::seal`/`open` at `encrypt_final`/
//!   `decrypt_final`, unlike the OpenSSL backend, which streams ciphertext
//!   out of every `encrypt_update`/`decrypt_update` call. This is fully
//!   PKCS#11-conformant (the trait contract never requires a specific
//!   per-call output split, only that `encryption_len`/`decryption_len`
//!   correctly predict each call -- which this implementation does for its
//!   own behavior) but uses more memory for very large single operations
//!   and will not byte-for-byte match the OpenSSL backend's per-call
//!   output sizes in shared tests that assert on them.
//! - CKM_AES_CCM does not have this limitation: `CK_CCM_PARAMS` declares
//!   the total plaintext length (`ulDataLen`) upfront, so this
//!   implementation calls AWS-LC's one-shot `AesCcm::seal`/`open` as soon
//!   as the buffered data reaches that declared length (during whichever
//!   `encrypt_update`/`decrypt_update` call completes it), deferring only
//!   the tag to `encrypt_final` -- matching the OpenSSL backend's actual
//!   per-call output shape.
//!
//! Note: unlike this file, `crate::ossl::aes` also defines a private,
//! backend-agnostic `AesKDFOperation` type directly inside `src/aes.rs`
//! itself (not part of the `crate::ossl::aes`/`crate::awslc::aes`
//! surface), so no equivalent type is needed here.

use crate::error::{Error, Result};
use crate::mechanism::{
    Decryption, Encryption, Mac, MechOperation, Mechanisms, MessageOperation,
    MsgDecryption, MsgEncryption, Sign, Verify, VerifySignature,
};
use crate::misc::{bytes_to_vec, zeromem};
use crate::object::Object;
use crate::pkcs11::*;

use crate::lowlevel::cipher::{
    AesCcm, AesGcm, AesKeyWrap, BlockCipher, CipherMode, OneShotAead, SecretBuf,
};
use crate::lowlevel::mac::Cmac;
#[cfg(feature = "fips")]
use crate::native::aes_iv::fips_approval_aead;
use crate::native::aes_iv::{generate_iv, AesIvData};

use constant_time_eq::constant_time_eq;

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

/// The AES block size, in bytes (128 bits), mirroring
/// `crate::aes::AES_BLOCK_SIZE` (duplicated here rather than imported to
/// keep this module's classic-mode code self-contained and independent of
/// `crate::aes`'s own internal layout).
const AES_BLOCK_SIZE: usize = 16;

/// Half an AES block (64 bits), the unit RFC 3394/5649 key wrap operates
/// in: wrapped output always grows by one semiblock over the (possibly
/// padded) input, and plain `CKM_AES_KEY_WRAP`/`_PKCS7`'s padding rounds
/// up to a semiblock boundary rather than a full block, mirroring
/// `crate::ossl::aes::AES_KW_SEMIBLOCK`.
const AES_KW_SEMIBLOCK: usize = AES_BLOCK_SIZE / 2;

// `MAX_CCM_BUF`/`MIN_RANDOM_IV_BITS` are backend-agnostic policy
// thresholds (not FIPS 197/SP 800-38x-mandated values), defined once in
// crate::aes and re-exported here -- see that module's doc comments for
// the exact rationale/values. This backend needs `MAX_CCM_BUF` for
// classic GCM too, not just CCM (the reference only needs it for CCM,
// since its classic GCM streams through OpenSSL's incremental
// `EVP_CIPHER` API instead of buffering; this backend's classic GCM has
// no incremental AEAD update in AWS-LC to stream through -- see the
// module-level doc comment -- and buffers the *entire* message
// unconditionally, so without this cap a large enough single operation
// could accumulate unbounded memory here as well).
pub use crate::aes::{MAX_CCM_BUF, MIN_RANDOM_IV_BITS};

/// Reads a `CK_GCM_MESSAGE_PARAMS` out of a raw `(param, paramlen)` pair,
/// the same way `src/ossl/aes.rs`'s `check_msg_params`/`init_msg_params`
/// do it (via `cast_params`), but reusing `CK_MECHANISM::get_parameters`
/// (already used the same way throughout the crate, e.g.
/// `mech.get_parameters::<CK_GCM_PARAMS>()` in `src/ossl/aes.rs`) instead
/// of duplicating that unsafe read here. `CK_GCM_MESSAGE_PARAMS` is `Copy`
/// (it only holds two raw pointers and some integers/enum values), so
/// reading it by value keeps the `pIv`/`pTag` pointers -- which still
/// point at the real caller-owned buffers -- intact.
fn read_gcm_message_params(
    param: CK_VOID_PTR,
    paramlen: CK_ULONG,
) -> Result<CK_GCM_MESSAGE_PARAMS> {
    let holder = CK_MECHANISM {
        mechanism: CK_UNAVAILABLE_INFORMATION,
        pParameter: param,
        ulParameterLen: paramlen,
    };
    holder.get_parameters::<CK_GCM_MESSAGE_PARAMS>()
}

/// Reads a `CK_CCM_MESSAGE_PARAMS` out of a raw `(param, paramlen)` pair,
/// the same way [`read_gcm_message_params`] does for GCM.
/// `CK_CCM_MESSAGE_PARAMS` is `Copy` (raw pointers plus integers/enum
/// values), so reading it by value keeps the `pNonce`/`pMAC` pointers --
/// which still point at the real caller-owned buffers -- intact.
fn read_ccm_message_params(
    param: CK_VOID_PTR,
    paramlen: CK_ULONG,
) -> Result<CK_CCM_MESSAGE_PARAMS> {
    let holder = CK_MECHANISM {
        mechanism: CK_UNAVAILABLE_INFORMATION,
        pParameter: param,
        ulParameterLen: paramlen,
    };
    holder.get_parameters::<CK_CCM_MESSAGE_PARAMS>()
}

/// Validates a `CK_CCM_MESSAGE_PARAMS`'s nonce length and declared data
/// length, mirroring `crate::ossl::aes::AesOperation::init_msg_params`'s
/// `CKM_AES_CCM` arm (which in turn matches `init_params`'s classic
/// `CKM_AES_CCM` arm, already ported to this file's `classic_new` for the
/// non-message path): nonce length must be in `[7, 13]` (NIST SP 800-38C),
/// and the declared data length must fit in the `L = 15 - nonceLen` byte
/// counter field CCM's construction reserves for it.
fn ccm_max_data_len(nonce_len: CK_ULONG) -> Result<CK_ULONG> {
    if nonce_len < 7 || nonce_len > 13 {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }
    let l = 15 - nonce_len;
    Ok((1 as CK_ULONG)
        .checked_shl(8 * l as u32)
        .unwrap_or(CK_ULONG::MAX))
}

/// Extracts the raw AES key bytes from a PKCS#11 `Object`.
fn key_bytes(key: &Object) -> Result<Vec<u8>> {
    Ok(key.get_attr_as_bytes(CKA_VALUE)?.clone())
}

/// Per-mode state for a classic (non-message) `Encryption`/`Decryption`
/// operation, mirroring the mechanism-specific parts of
/// `crate::ossl::aes::AesOperation`'s combined `ctx`/`params`/`buffer`
/// fields, but split by mode since `awslc::cipher`'s primitives are
/// shaped very differently per mode (a directional streaming
/// `BlockCipher` for ECB/CBC/CBC-PAD/CTR/OFB/CFB*, vs. one-shot AEAD
/// `seal`/`open` calls for GCM/CCM).
#[derive(Debug)]
enum ClassicMode {
    /// ECB/CBC/CBC-PAD/CTR/OFB/CFB1/CFB8/CFB128: a directional
    /// `BlockCipher` held alive for the operation's entire lifetime.
    /// Empirically verified (see the task report) that repeated
    /// `encrypt()`/`decrypt()` calls on the *same* `BlockCipher` instance
    /// correctly continue CBC chaining / CTR-OFB-CFB keystream state
    /// across calls, as long as intermediate calls pass `padding: false`
    /// and only the very last call (for CBC-PAD) passes `padding: true`.
    Block {
        cipher: BlockCipher,
        /// True only for `CKM_AES_CBC_PAD`.
        padded: bool,
        /// True for ECB/CBC/CBC-PAD: input must be accumulated up to
        /// whole blocks before being fed to `cipher` (trailing partial
        /// bytes carried in `buffer` between calls). False for
        /// CTR/OFB/CFB*: arbitrary-length chunks pass straight through,
        /// `buffer` stays empty.
        block_aligned: bool,
        /// Encrypt: the trailing partial block not yet fed to `cipher`
        /// (0..AES_BLOCK_SIZE-1 bytes). Decrypt, CBC-PAD specifically:
        /// holds back a FULL extra block at all times (1..=AES_BLOCK_SIZE
        /// bytes) -- unlike a long-lived OpenSSL `EVP_CIPHER_CTX`, which
        /// internally defers the last block itself when padding is
        /// enabled, `BlockCipher::decrypt` runs Update+Final together on
        /// every call, so this holdback has to be done explicitly here to
        /// avoid emitting the still-padded last block early (verified
        /// empirically -- see the task report).
        buffer: Vec<u8>,
        /// CTR-only: number of AES-block operations performed so far.
        blockctr: u128,
        /// CTR-only: maximum number of AES-block operations allowed
        /// before the (narrower-than-128-bit) counter would silently
        /// wrap; 0 means "no limit" (the common case, a full 128-bit
        /// counter). Mirrors `crate::ossl::aes::AesParams::maxblocks`.
        maxblocks: u128,
    },
    /// `CKM_AES_CCM`. `CK_CCM_PARAMS` declares the total plaintext length
    /// (`ulDataLen`) upfront, so unlike GCM below, this can (and does)
    /// call AWS-LC's one-shot `AesCcm::seal`/`open` as soon as `buffer`
    /// reaches that declared length, during whichever `encrypt_update`/
    /// `decrypt_update` call completes it -- matching the OpenSSL
    /// backend's actual per-call output shape (ciphertext during update,
    /// tag during `encrypt_final`).
    Ccm {
        nonce: Vec<u8>,
        aad: Vec<u8>,
        taglen: usize,
        datalen: usize,
        /// Encrypt: buffered plaintext until `datalen` bytes have
        /// arrived, then cleared. Decrypt: buffered ciphertext+tag until
        /// `datalen + taglen` bytes have arrived, then cleared.
        buffer: Vec<u8>,
        /// Encrypt only: the tag computed once `seal` ran, retrieved by
        /// `encrypt_final`. Always `None` for decrypt (there is nothing
        /// left to emit at `decrypt_final` once `open` has run).
        tag: Option<Vec<u8>>,
        /// True once `seal`/`open` has actually run (buffer reached its
        /// target length). `encrypt_final`/`decrypt_final` require this.
        done: bool,
    },
    /// `CKM_AES_GCM` (classic). Unlike CCM, `CK_GCM_PARAMS` has no
    /// upfront total-length field, and AWS-LC's `AesGcm` is a one-shot
    /// AEAD (no incremental update API), so there is no equivalent
    /// early-completion point to detect. This implementation therefore
    /// buffers the *entire* message and calls `AesGcm::seal`/`open`
    /// exactly once, at `encrypt_final`/`decrypt_final` -- see the
    /// module-level doc comment for what this means for callers.
    Gcm {
        iv: Vec<u8>,
        aad: Vec<u8>,
        taglen: usize,
        /// Encrypt: buffered plaintext. Decrypt: buffered ciphertext+tag
        /// (the tag is always the trailing `taglen` bytes, per the
        /// classic PKCS#11 convention of appending it to the ciphertext).
        buffer: Vec<u8>,
    },
}

impl Drop for ClassicMode {
    fn drop(&mut self) {
        match self {
            ClassicMode::Block { buffer, .. } => zeromem(buffer),
            ClassicMode::Ccm {
                nonce,
                aad,
                buffer,
                tag,
                ..
            } => {
                zeromem(nonce);
                zeromem(aad);
                zeromem(buffer);
                if let Some(t) = tag {
                    zeromem(t);
                }
            }
            ClassicMode::Gcm {
                iv, aad, buffer, ..
            } => {
                zeromem(iv);
                zeromem(aad);
                zeromem(buffer);
            }
        }
    }
}

/// Which `CKM_AES_KEY_WRAP*` variant a [`KeyWrapCipherState`] is using.
#[derive(Debug, Clone, Copy)]
enum KeyWrapVariant {
    /// `CKM_AES_KEY_WRAP`: plain (unpadded) RFC 3394 wrap.
    Plain,
    /// `CKM_AES_KEY_WRAP_PKCS7`: RFC 3394 wrap of PKCS7-padded input.
    Pkcs7,
    /// `CKM_AES_KEY_WRAP_KWP`: RFC 5649 padded wrap.
    Kwp,
}

/// Implements `Debug` for a struct that holds secret key material,
/// printing the fields named in `redact` as `"[REDACTED]"` and every
/// other named field verbatim. Mirrors the identically-named macro in
/// `awslc/src/cipher.rs` (this crate can't reuse that one directly
/// across the crate boundary, and this file's structs -- unlike
/// everything in the `awslc` crate -- can have a real
/// `#[cfg(feature = "fips")]`-gated field, which `show_fips` below
/// handles). Removes the boilerplate every hand-written redacting `Debug`
/// impl in this file would otherwise duplicate, and -- unlike a plain
/// `#[derive(Debug)]` -- forces whoever adds a new field to explicitly
/// decide whether it's secret rather than silently inheriting a leak.
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

/// State for a classic (non-message) `Encryption`/`Decryption` operation
/// using `CKM_AES_KEY_WRAP`/`_PKCS7`/`_KWP` as a generic cipher on
/// arbitrary data, matching the reference backend's own treatment of
/// these mechanisms as "just another `EncAlg`" (`src/ossl/aes.rs`'s
/// `EncAlg::AesWrap`/`AesWrapPad`). This is distinct from `wrap`/`unwrap`,
/// which use these same mechanisms to wrap/unwrap a key OBJECT instead
/// and never construct an `AesOperation` at all.
// `kw: AesKeyWrap` already redacts itself via its own `Debug` impl, but a
// derived `Debug` here would still print `buffer`, which can hold
// plaintext key material mid-wrap/unwrap. Redact it too, for the same
// reason.
redacting_debug!(KeyWrapCipherState {
    redact: [buffer],
    show: [kw, variant, iv, prefix],
});

struct KeyWrapCipherState {
    kw: AesKeyWrap,
    variant: KeyWrapVariant,
    /// Custom 8-byte IV from `mech.pParameter`, for `Plain`/`Pkcs7`
    /// (`None` uses RFC 3394's default).
    iv: Option<[u8; 8]>,
    /// Custom 4-byte AIV prefix from `mech.pParameter`, for `Kwp` (`None`
    /// uses RFC 5649's default constant).
    prefix: Option<[u8; 4]>,
    /// Accumulates every `encrypt_update`/`decrypt_update` call's input:
    /// `AesKeyWrap` has no real incremental operation, so nothing is
    /// wrapped/unwrapped until `encrypt_final`/`decrypt_final` runs it over
    /// everything buffered here (mirroring how `ClassicMode::Ccm`/`Gcm`
    /// also buffer a whole message before their own one-shot primitive
    /// call).
    buffer: Vec<u8>,
}

/// An active AES operation: either the one-shot `CKM_AES_GCM`
/// message-mode path (`msg_encrypt_init`/`msg_decrypt_init`), a classic
/// (non-message) `Encryption`/`Decryption` operation (`encrypt_new`/
/// `decrypt_new`) covering ECB, CBC, CBC-PAD, CTR, OFB, CFB1/8/128, GCM
/// and CCM (`classic`), or that same classic `Encryption`/`Decryption`
/// API used with `CKM_AES_KEY_WRAP`/`_PKCS7`/`_KWP` on arbitrary data
/// (`key_wrap`, see [`KeyWrapCipherState`]). `wrap`/`unwrap` (AES
/// key-wrap of a key OBJECT via `C_WrapKey`/`C_UnwrapKey`) are separate
/// one-shot associated functions built directly on
/// `awslc::cipher::AesKeyWrap`, not part of this struct's own state
/// machine at all (see `wrap`'s doc comment for why).
// A derived `Debug` would print `key` -- the raw AES key -- in cleartext
// on any `{:?}` format of this type. `classic`/`key_wrap` are
// `Option<ClassicMode>`/`Option<KeyWrapCipherState>`, both of which
// already redact their own key material via their own `Debug` impls, so
// they're safe to show as-is.
redacting_debug!(AesOperation {
    redact: [key],
    show: [
        mech,
        finalized,
        classic,
        encrypting,
        in_use,
        msg_iv,
        key_wrap,
        msg_buffer,
        msg_aad,
        msg_tag_len,
        msg_ccm_data_len,
    ],
    show_fips: [fips_approval],
});

pub struct AesOperation {
    mech: CK_MECHANISM_TYPE,
    key: SecretBuf,
    finalized: bool,
    /// `Some` only for classic-mode operations (`encrypt_new`/
    /// `decrypt_new`); always `None` for message-mode operations, which
    /// don't use any of this state.
    classic: Option<ClassicMode>,
    /// Direction for classic-mode operations (true = encrypt, false =
    /// decrypt); meaningless for message-mode operations.
    encrypting: bool,
    /// Set once `encrypt_update`/`decrypt_update` has been called at
    /// least once; classic-mode `encrypt_final`/`decrypt_final` require
    /// this, mirroring `crate::ossl::aes::AesOperation`'s `in_use` flag.
    in_use: bool,
    /// IV/nonce-generation state for message-mode GCM/CCM operations
    /// (`msg_encrypt_gcm`/`msg_encrypt_ccm`/`msg_decrypt_gcm`/
    /// `msg_decrypt_ccm`), mirroring `crate::ossl::aes::AesParams`'s `iv`
    /// field. `None` for classic-mode operations, which parse their IV
    /// directly into `ClassicMode` at construction time instead (see
    /// `init_classic_mode`'s doc comment: classic mode has no
    /// IV-generator support to drive through `generate_iv`). Not
    /// `fips`-gated: IV-generator expansion (`CKG_GENERATE`/
    /// `CKG_GENERATE_COUNTER`/`CKG_GENERATE_COUNTER_XOR`, non-zero
    /// `ulIvFixedBits`) applies to both `awslc` and `awslc-fips` builds.
    msg_iv: Option<AesIvData>,
    /// `Some` only for a classic (non-message) `Encryption`/`Decryption`
    /// operation using `CKM_AES_KEY_WRAP`/`_PKCS7`/`_KWP` as a generic
    /// cipher on arbitrary data (distinct from `wrap`/`unwrap`'s own use
    /// of these same mechanisms to wrap/unwrap a key OBJECT, which never
    /// constructs an `AesOperation` at all). Kept out of `ClassicMode`
    /// since `AesKeyWrap` isn't a `BlockCipher`/AEAD shape (see `wrap`'s
    /// doc comment), and this one-shot construct has no real incremental
    /// update, so a small separate field is simpler than threading a new
    /// variant through every existing `ClassicMode` match arm. Mutually
    /// exclusive with `classic`: exactly one of the two is `Some`.
    key_wrap: Option<KeyWrapCipherState>,
    /// Accumulates a message-mode `Begin`/`Next`/`Final` operation's
    /// plaintext (encrypt) or ciphertext (decrypt) across `Next` calls:
    /// AWS-LC's `AesGcm`/`AesCcm` are one-shot primitives with no
    /// incremental update (same reasoning as `key_wrap`'s own buffer), so
    /// the real seal/open call happens once, in `Final`, over everything
    /// buffered here plus that call's own last chunk. Empty outside a
    /// `Begin`/`Next`/`Final` bracket.
    msg_buffer: Vec<u8>,
    /// Associated authenticated data from `msg_encrypt_begin`/
    /// `msg_decrypt_begin`, carried forward to the real seal/open call
    /// `msg_encrypt_final`/`msg_decrypt_final` performs (AAD is supplied
    /// once, at `Begin`, not accumulated across `Next` calls).
    msg_aad: Vec<u8>,
    /// Tag/MAC length established by `msg_encrypt_begin`/
    /// `msg_decrypt_begin`, in bytes.
    msg_tag_len: Option<usize>,
    /// CCM's declared total data length (`CK_CCM_MESSAGE_PARAMS::
    /// ulDataLen`), which the accumulated `msg_buffer` must exactly equal
    /// by `Final` (NIST SP 800-38C requires the total length up front,
    /// unlike GCM). `None` for GCM (no such declaration) and outside a
    /// `Begin`/`Next`/`Final` bracket.
    msg_ccm_data_len: Option<usize>,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

/// Constructs the one-shot AEAD primitive `mech` implies (`CKM_AES_GCM`/
/// `CKM_AES_CCM` are the only two mechanisms message mode and classic-mode
/// GCM/CCM ever use), boxed as `dyn OneShotAead` so every call site below
/// needs exactly one `seal`/`open` call instead of a `match self.mech {
/// CKM_AES_GCM => ..., CKM_AES_CCM => ... }` repeating the same two lines
/// with only the type name differing.
fn new_one_shot_aead(
    mech: CK_MECHANISM_TYPE,
    key: &[u8],
    tag_len: usize,
) -> Result<Box<dyn OneShotAead>> {
    Ok(match mech {
        CKM_AES_GCM => Box::new(AesGcm::new(key, tag_len)?),
        CKM_AES_CCM => Box::new(AesCcm::new(key, tag_len)?),
        _ => return Err(CKR_GENERAL_ERROR)?,
    })
}

impl AesOperation {
    /// Registers `CKM_AES_GCM` (message mode, used by
    /// `src/encryption.rs`'s `aes_gcm_encrypt`/`aes_gcm_decrypt`) plus
    /// every classic mechanism this module implements, mirroring
    /// `crate::ossl::aes::AesOperation::register_mechanisms`'s grouping
    /// by `CK_MECHANISM_INFO`/flag set (`crate::aes::AES_MECHS[0]` for
    /// the plain `CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP` group,
    /// `[1]` for the AEAD group that also carries the message-mode
    /// flags, `[2]` for the encrypt/decrypt-only OFB/CFB group).
    /// Unlike the OpenSSL backend, `CKM_AES_CTS` is deliberately NOT
    /// registered here: AWS-LC has no ciphertext-stealing primitive at
    /// all, and `C_GetMechanismList`/`C_GetMechanismInfo` must not report
    /// a mechanism that then unconditionally fails on every real
    /// `C_EncryptInit`/`C_DecryptInit` call (PKCS#11 v3.2 §5.2) --
    /// matching how X448/Ed448/SLH-DSA are handled elsewhere in this
    /// backend (absent from the relevant mechanism list, not
    /// registered-then-rejected). `CKM_AES_KEY_GEN` (`AES_MECHS[3]`, the
    /// `CKF_GENERATE`-only entry) is also registered here, matching
    /// `crate::ossl::aes::AesOperation::register_mechanisms`, so
    /// `AesMechanism::generate_key` (`src/aes.rs`) is reachable for this
    /// backend too -- without it, `C_GenerateKey(CKM_AES_KEY_GEN, ...)`
    /// would fail with "mechanism not found" and this backend could only
    /// ever consume imported AES keys, never generate one.
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_KEY_WRAP,
            CKM_AES_KEY_WRAP_KWP,
            CKM_AES_KEY_WRAP_PKCS7,
        ] {
            mechs.add_mechanism(*ckm, &crate::aes::AES_MECHS[0]);
        }
        for ckm in &[CKM_AES_GCM, CKM_AES_CCM] {
            mechs.add_mechanism(*ckm, &crate::aes::AES_MECHS[1]);
        }
        // Matches `crate::ossl::aes::AesOperation::register_mechanisms`'s
        // own `#[cfg(not(feature = "fips"))]` gate on this same group: AWS-
        // LC-FIPS's actual validated certificate scope for these modes
        // isn't confirmed (unlike GCM/CCM/ECB/CBC/CTR/CMAC, which this
        // backend's FIPS service-indicator table in `src/fips/indicators.rs`
        // does cover), so this backend declines to advertise them under
        // `fips` rather than claim an approval status it can't vouch for --
        // the same conservative posture `src/enabled.rs`'s ML-DSA-under-
        // `awslc-fips` exclusion documents. Plain (non-FIPS) `awslc` is
        // unaffected.
        #[cfg(not(feature = "fips"))]
        for ckm in &[CKM_AES_OFB, CKM_AES_CFB128, CKM_AES_CFB1, CKM_AES_CFB8] {
            mechs.add_mechanism(*ckm, &crate::aes::AES_MECHS[2]);
        }
        mechs.add_mechanism(CKM_AES_KEY_GEN, &crate::aes::AES_MECHS[3]);
    }

    /// Instantiates a new classic (non-message) Encryption operation.
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Self::classic_new(mech, key, true)
    }

    /// Instantiates a new classic (non-message) Decryption operation.
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Self::classic_new(mech, key, false)
    }

    /// Shared `encrypt_new`/`decrypt_new` implementation: validates the
    /// key, parses the mechanism's parameters and builds the appropriate
    /// `ClassicMode` for it. `CKM_AES_KEY_WRAP*` mechanisms are diverted
    /// to [`Self::key_wrap_classic_new`] instead, since they build a
    /// `KeyWrapCipherState`, not a `ClassicMode`.
    fn classic_new(
        mech: &CK_MECHANISM,
        key: &Object,
        encrypting: bool,
    ) -> Result<AesOperation> {
        if matches!(
            mech.mechanism,
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_PKCS7 | CKM_AES_KEY_WRAP_KWP
        ) {
            return Self::key_wrap_classic_new(mech, key, encrypting);
        }
        // `keybytes` holds the raw AES key from here on. It's a
        // `SecretBuf`, not a plain `Vec<u8>`, so every early return
        // between acquiring it and handing it off to the successfully-
        // constructed `AesOperation` scrubs it automatically via its own
        // `Drop` -- no manual scrub-then-return needed on any fallible
        // path (mirrors the guarantee `OsslSecret`'s own unconditional
        // `Drop` gives the reference backend).
        let keybytes = SecretBuf::from_vec(key_bytes(key)?);
        crate::aes::check_key_len(keybytes.len())?;

        // Unlike `crate::ossl::aes`'s `cipher_initialize`, `init_classic_mode`
        // never itself invokes an AWS-LC crypto primitive (it only parses
        // mechanism parameters into a `ClassicMode` value) -- the real
        // `EVP_{En,De}cryptInit_ex`/`AesGcm::new`/`AesCcm::new` calls happen
        // later, in `classic_encrypt_update`/`_final`/`classic_decrypt_update`/
        // `_final`. Bracketing this constructor with `clear()`/`update()`
        // would therefore observe no service-indicator movement and (on
        // `awslc-fips`, where "nothing happened" reads as "not approved",
        // the opposite polarity from `ossl-backend`) permanently poison
        // `fips_approval` to `Some(false)` before any real work has even
        // started. So `fips_approval` starts untouched here; classic-mode
        // approval is established either by the explicit AEAD IV/tag check
        // just below (GCM/CCM) or by the `clear()`/`update()` pairs placed
        // directly around each real cipher call in the four dispatch
        // functions above (every other mode).
        #[cfg(feature = "fips")]
        let fips_approval = FipsApproval::init();

        let classic = Self::init_classic_mode(mech, &keybytes, encrypting)?;

        #[allow(unused_mut)]
        let mut op = AesOperation {
            mech: mech.mechanism,
            key: keybytes,
            finalized: false,
            classic: Some(classic),
            encrypting,
            in_use: false,
            msg_iv: None,
            key_wrap: None,
            msg_buffer: Vec::new(),
            msg_aad: Vec::new(),
            msg_tag_len: None,
            msg_ccm_data_len: None,
            #[cfg(feature = "fips")]
            fips_approval,
        };

        #[cfg(feature = "fips")]
        if op.mech == CKM_AES_GCM || op.mech == CKM_AES_CCM {
            let (iv_buf, taglen) = match op.classic.as_ref().unwrap() {
                ClassicMode::Gcm { iv, taglen, .. } => (iv.clone(), *taglen),
                ClassicMode::Ccm { nonce, taglen, .. } => {
                    (nonce.clone(), *taglen)
                }
                _ => unreachable!(),
            };
            let iv_data = AesIvData {
                buf: iv_buf,
                fixedbits: 0,
                generator: CKG_NO_GENERATE,
                counter: 0,
                maxcount: 0,
            };
            let op_flag = if op.encrypting {
                CKF_ENCRYPT
            } else {
                CKF_DECRYPT
            };
            fips_approval_aead(
                &mut op.fips_approval,
                &iv_data,
                op_flag,
                taglen,
            )?;
        }

        Ok(op)
    }

    /// Builds an `AesOperation` whose `key_wrap` (not `classic`) field is
    /// populated, for `CKM_AES_KEY_WRAP`/`_PKCS7`/`_KWP` used as a generic
    /// cipher via `encrypt_new`/`decrypt_new`. Parses the same optional
    /// custom IV/AIV-prefix `mech.pParameter` that `wrap`/`unwrap` accept
    /// (see `parse_kw_iv`/`parse_kwp_prefix`). `key` is empty: the raw
    /// bytes aren't needed once `AesKeyWrap::new` has built its own key
    /// schedule from them (`key_wrap_cipher` already scrubs its own
    /// temporary copy), unlike classic mode's `ClassicMode`, which needs
    /// `self.key` again on every `encrypt_update`/`decrypt_update` call.
    fn key_wrap_classic_new(
        mech: &CK_MECHANISM,
        key: &Object,
        encrypting: bool,
    ) -> Result<AesOperation> {
        let kw = Self::key_wrap_cipher(key)?;
        let (variant, iv, prefix) = match mech.mechanism {
            CKM_AES_KEY_WRAP => (
                KeyWrapVariant::Plain,
                Self::parse_kw_iv(mech, CKR_ARGUMENTS_BAD)?,
                None,
            ),
            CKM_AES_KEY_WRAP_PKCS7 => (
                KeyWrapVariant::Pkcs7,
                Self::parse_kw_iv(mech, CKR_ARGUMENTS_BAD)?,
                None,
            ),
            CKM_AES_KEY_WRAP_KWP => (
                KeyWrapVariant::Kwp,
                None,
                Self::parse_kwp_prefix(mech, CKR_ARGUMENTS_BAD)?,
            ),
            _ => unreachable!(),
        };
        Ok(AesOperation {
            mech: mech.mechanism,
            // Unused for this mechanism family: the key-encryption key
            // lives in `key_wrap.kw` (an `AesKeyWrap`) instead.
            key: SecretBuf::from_vec(Vec::new()),
            finalized: false,
            classic: None,
            encrypting,
            in_use: false,
            msg_iv: None,
            key_wrap: Some(KeyWrapCipherState {
                kw,
                variant,
                iv,
                prefix,
                buffer: Vec::new(),
            }),
            msg_buffer: Vec::new(),
            msg_aad: Vec::new(),
            msg_tag_len: None,
            msg_ccm_data_len: None,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// `Encryption::encrypt_final` for a `key_wrap` operation: wraps
    /// everything `encrypt_update` has buffered so far (AES-KW has no real
    /// incremental output, so every `encrypt_update` call only buffers --
    /// see `key_wrap_encrypt_update`). Brackets the real `AesKeyWrap` call
    /// with `fips_approval.clear()`/`update()`, the same convention
    /// `classic_encrypt_update`/`_final` use for every other mode --
    /// AWS-LC's `AES_wrap_key`/`_padded` genuinely call
    /// `FIPS_service_indicator_update_state()` internally (confirmed
    /// against `crypto/fipsmodule/aes/key_wrap.c`), so this observes a
    /// real indicator, not a guess. A `CKR_BUFFER_TOO_SMALL` result is
    /// non-fatal per the `Encryption`/`Decryption` trait contract: the
    /// buffered plaintext and `finalized` are left untouched so the caller
    /// can retry with a bigger buffer.
    fn key_wrap_finalize_encrypt(
        &mut self,
        cipher: &mut [u8],
    ) -> Result<usize> {
        let variant = self.key_wrap.as_ref().unwrap().variant;
        let iv = self.key_wrap.as_ref().unwrap().iv;
        let prefix = self.key_wrap.as_ref().unwrap().prefix;
        let result = {
            let state = self.key_wrap.as_ref().unwrap();
            let kw = &state.kw;
            #[cfg(feature = "fips")]
            self.fips_approval.clear();
            let r = match variant {
                KeyWrapVariant::Plain => {
                    Self::wrap_plain(kw, &state.buffer, iv.as_ref(), cipher)
                }
                KeyWrapVariant::Pkcs7 => {
                    let mut data = state.buffer.clone();
                    let r =
                        Self::wrap_pkcs7(kw, &mut data, iv.as_ref(), cipher);
                    zeromem(&mut data);
                    r
                }
                KeyWrapVariant::Kwp => {
                    Self::wrap_kwp(kw, &state.buffer, prefix, cipher)
                }
            };
            #[cfg(feature = "fips")]
            self.fips_approval.update();
            r
        };
        match &result {
            Err(e) if e.rv() == CKR_BUFFER_TOO_SMALL => (),
            _ => {
                self.finalized = true;
                zeromem(&mut self.key_wrap.as_mut().unwrap().buffer);
            }
        }
        result.map_err(|e| {
            if e.rv() == CKR_BUFFER_TOO_SMALL {
                e
            } else {
                self.op_err(e.rv())
            }
        })
    }

    /// `Decryption::decrypt_final` for a `key_wrap` operation. See
    /// `key_wrap_finalize_encrypt`'s doc comment for the FIPS-approval
    /// rationale. Unlike the wrap side, `AesKeyWrap`'s unwrap has no
    /// buffer-size-query mode -- the real unwrapped length is only known
    /// after actually unwrapping -- so a too-small caller buffer is
    /// detected only after the fact; when that happens, the buffered
    /// ciphertext and `finalized` are left untouched (matching the
    /// `CKR_BUFFER_TOO_SMALL` contract) so a retry with a bigger buffer
    /// redoes the unwrap instead of operating on already-scrubbed state.
    fn key_wrap_finalize_decrypt(&mut self, plain: &mut [u8]) -> Result<usize> {
        let variant = self.key_wrap.as_ref().unwrap().variant;
        let iv = self.key_wrap.as_ref().unwrap().iv;
        let prefix = self.key_wrap.as_ref().unwrap().prefix;
        let result: std::result::Result<Vec<u8>, Error> = {
            let state = self.key_wrap.as_ref().unwrap();
            let kw = &state.kw;
            #[cfg(feature = "fips")]
            self.fips_approval.clear();
            let r = match variant {
                KeyWrapVariant::Plain => {
                    Self::unwrap_plain(kw, &state.buffer, iv.as_ref())
                }
                KeyWrapVariant::Pkcs7 => {
                    Self::unwrap_pkcs7(kw, &state.buffer, iv.as_ref())
                }
                KeyWrapVariant::Kwp => {
                    Self::unwrap_kwp(kw, &state.buffer, prefix)
                }
            };
            #[cfg(feature = "fips")]
            self.fips_approval.update();
            r
        };
        let mut out = match result {
            Ok(o) => o,
            Err(e) => {
                self.finalized = true;
                zeromem(&mut self.key_wrap.as_mut().unwrap().buffer);
                return Err(self.op_err(e.rv()));
            }
        };
        if plain.len() < out.len() {
            let needed = out.len();
            zeromem(&mut out);
            return Err(Error::buf_too_small(needed));
        }
        self.finalized = true;
        zeromem(&mut self.key_wrap.as_mut().unwrap().buffer);
        plain[..out.len()].copy_from_slice(&out);
        let n = out.len();
        zeromem(&mut out);
        Ok(n)
    }

    /// Parses `mech`'s parameters and builds the `ClassicMode` for it,
    /// mirroring `crate::ossl::aes::AesOperation::init_params` combined
    /// with the mode-specific parts of its `cipher_initialize` (this
    /// backend has no IV-generator support to port: every classic-mode
    /// mechanism here always uses `CKG_NO_GENERATE`/caller-supplied IVs,
    /// same as the reference's own `AesIvData::simple`).
    fn init_classic_mode(
        mech: &CK_MECHANISM,
        key: &[u8],
        encrypting: bool,
    ) -> Result<ClassicMode> {
        match mech.mechanism {
            CKM_AES_ECB => {
                let cipher =
                    BlockCipher::new(CipherMode::Ecb, key, None, encrypting)?;
                Ok(ClassicMode::Block {
                    cipher,
                    padded: false,
                    block_aligned: true,
                    buffer: Vec::new(),
                    blockctr: 0,
                    maxblocks: 0,
                })
            }
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                let iv = bytes_to_vec(
                    mech.pParameter,
                    usize::try_from(mech.ulParameterLen)?,
                );
                let cipher = BlockCipher::new(
                    CipherMode::Cbc,
                    key,
                    Some(&iv),
                    encrypting,
                )?;
                Ok(ClassicMode::Block {
                    cipher,
                    padded: mech.mechanism == CKM_AES_CBC_PAD,
                    block_aligned: true,
                    buffer: Vec::new(),
                    blockctr: 0,
                    maxblocks: 0,
                })
            }
            CKM_AES_CTR => {
                let params = mech.get_parameters::<CK_AES_CTR_PARAMS>()?;
                let iv = params.cb.to_vec();
                let ctrbits = usize::try_from(params.ulCounterBits)
                    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let maxblocks = Self::ctr_maxblocks(ctrbits, &iv)?;
                let cipher = BlockCipher::new(
                    CipherMode::Ctr,
                    key,
                    Some(&iv),
                    encrypting,
                )?;
                Ok(ClassicMode::Block {
                    cipher,
                    padded: false,
                    block_aligned: false,
                    buffer: Vec::new(),
                    blockctr: 0,
                    maxblocks,
                })
            }
            CKM_AES_OFB | CKM_AES_CFB1 | CKM_AES_CFB8 | CKM_AES_CFB128 => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                let iv = bytes_to_vec(
                    mech.pParameter,
                    usize::try_from(mech.ulParameterLen)?,
                );
                let mode = match mech.mechanism {
                    CKM_AES_OFB => CipherMode::Ofb,
                    CKM_AES_CFB1 => CipherMode::Cfb1,
                    CKM_AES_CFB8 => CipherMode::Cfb8,
                    CKM_AES_CFB128 => CipherMode::Cfb128,
                    _ => unreachable!(),
                };
                let cipher =
                    BlockCipher::new(mode, key, Some(&iv), encrypting)?;
                Ok(ClassicMode::Block {
                    cipher,
                    padded: false,
                    block_aligned: false,
                    buffer: Vec::new(),
                    blockctr: 0,
                    maxblocks: 0,
                })
            }
            CKM_AES_GCM => {
                let params = mech.get_parameters::<CK_GCM_PARAMS>()?;
                if params.ulIvLen == 0
                    || params.ulIvLen > CK_ULONG::try_from(u32::MAX)?
                    || params.pIv == std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulAADLen > CK_ULONG::try_from(u32::MAX)? {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulTagBits < 8 || params.ulTagBits > 128 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let iv =
                    bytes_to_vec(params.pIv, usize::try_from(params.ulIvLen)?);
                let aad = bytes_to_vec(
                    params.pAAD,
                    usize::try_from(params.ulAADLen)?,
                );
                let taglen = (usize::try_from(params.ulTagBits)
                    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?
                    + 7)
                    / 8;
                Ok(ClassicMode::Gcm {
                    iv,
                    aad,
                    taglen,
                    buffer: Vec::new(),
                })
            }
            CKM_AES_CCM => {
                let params = mech.get_parameters::<CK_CCM_PARAMS>()?;
                if params.ulNonceLen < 7 || params.ulNonceLen > 13 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let l = 15 - params.ulNonceLen;
                let max_data_len: CK_ULONG = (1 as CK_ULONG)
                    .checked_shl(8 * l as u32)
                    .unwrap_or(CK_ULONG::MAX);
                if params.ulDataLen > max_data_len
                    || params.ulDataLen > (CK_ULONG::MAX - params.ulMACLen)
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulAADLen > CK_ULONG::try_from(u32::MAX - 1)? {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                match params.ulMACLen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
                let nonce = bytes_to_vec(
                    params.pNonce,
                    usize::try_from(params.ulNonceLen)?,
                );
                let aad = bytes_to_vec(
                    params.pAAD,
                    usize::try_from(params.ulAADLen)?,
                );
                let datalen = usize::try_from(params.ulDataLen)
                    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let taglen = usize::try_from(params.ulMACLen)
                    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                Ok(ClassicMode::Ccm {
                    nonce,
                    aad,
                    taglen,
                    datalen,
                    buffer: Vec::new(),
                    tag: None,
                    // Never pre-mark done, even for a zero-length (AAD-only)
                    // message: it still must go through one
                    // encrypt_update/decrypt_update call first, mirroring
                    // the reference's own `in_use` requirement.
                    done: false,
                })
            }
            // AWS-LC has no ciphertext-stealing primitive: this is a
            // permanent gap, not a "not yet implemented" placeholder.
            CKM_AES_CTS => Err(CKR_MECHANISM_INVALID)?,
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Computes the CTR-mode block-count limit for a counter narrower than
    /// the full 128-bit IV, mirroring
    /// `crate::ossl::aes::AesOperation::init_params`'s `CKM_AES_CTR` arm
    /// (including its own documented FIXME: arbitrary counter-bit
    /// wrapping isn't supported, only capping to avoid a silent wrap).
    /// Returns 0 (meaning "no limit") for a full 128-bit counter.
    fn ctr_maxblocks(ctrbits: usize, iv: &[u8]) -> Result<u128> {
        if ctrbits > AES_BLOCK_SIZE * 8 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if ctrbits == AES_BLOCK_SIZE * 8 {
            return Ok(0);
        }
        let mut maxblocks: u128 = (1u128 << ctrbits) - 1;
        let fulloctets = ctrbits / 8;
        let mut idx = 0usize;
        while fulloctets > idx {
            maxblocks -= u128::from(iv[15 - idx]) << (idx * 8);
            idx += 1;
        }
        let part = u128::try_from(ctrbits % 8)?;
        if part > 0 {
            maxblocks -= (u128::from(iv[15 - idx]) & part) << (idx * 8);
        }
        if maxblocks == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(maxblocks)
    }

    /// `encrypt_update` dispatch for classic-mode operations. Returns a
    /// plain `CK_RV` (rather than `Error`) so callers can decide whether
    /// to finalize the operation; every error here does, since the one
    /// non-fatal case (`CKR_BUFFER_TOO_SMALL`) is always checked by the
    /// caller *before* this runs (via `encryption_len`).
    fn classic_encrypt_update(
        classic: &mut ClassicMode,
        key: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
        #[cfg(feature = "fips")] fips_approval: &mut FipsApproval,
    ) -> std::result::Result<usize, CK_RV> {
        match classic {
            ClassicMode::Block {
                cipher: bc,
                block_aligned,
                buffer,
                blockctr,
                maxblocks,
                ..
            } => {
                if !*block_aligned {
                    if *maxblocks != 0 {
                        let reqblocks = ((plain.len() + AES_BLOCK_SIZE - 1)
                            / AES_BLOCK_SIZE)
                            as u128;
                        if *blockctr + reqblocks > *maxblocks {
                            return Err(CKR_DATA_LEN_RANGE);
                        }
                        *blockctr += reqblocks;
                    }
                    // Every call here reaches AWS-LC (no buffering for
                    // CTR/OFB/CFB), so this is always a real cipher
                    // operation, safe to bracket unconditionally -- see
                    // `classic_new`'s doc comment for why a bracket is only
                    // ever placed directly around a genuine crypto call.
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result = bc
                        .encrypt(plain, cipher, false)
                        .map_err(|_| CKR_DEVICE_ERROR);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    return result;
                }
                let total = buffer.len() + plain.len();
                let full = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                if full == 0 {
                    buffer.extend_from_slice(plain);
                    return Ok(0);
                }
                let take_from_plain = full - buffer.len();
                let mut tmp = Vec::with_capacity(full);
                tmp.extend_from_slice(buffer);
                tmp.extend_from_slice(&plain[..take_from_plain]);
                // `tmp` holds plaintext copied out of `buffer`/`plain`;
                // scrub it on every exit, not just the success path (the
                // early `?` return on an `encrypt` failure used to skip
                // the `zeromem` below entirely).
                #[cfg(feature = "fips")]
                fips_approval.clear();
                let result = bc.encrypt(&tmp, cipher, false);
                #[cfg(feature = "fips")]
                fips_approval.update();
                zeromem(&mut tmp);
                let n = result.map_err(|_| CKR_DEVICE_ERROR)?;
                buffer.clear();
                buffer.extend_from_slice(&plain[take_from_plain..]);
                Ok(n)
            }
            ClassicMode::Ccm {
                nonce,
                aad,
                taglen,
                datalen,
                buffer,
                tag,
                done,
            } => {
                if *done {
                    if !plain.is_empty() {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    return Ok(0);
                }
                // Mirrors `crate::ossl::aes`'s own `MAX_CCM_BUF` check in
                // its message-mode `msg_encrypt_next` (this backend always
                // buffers the whole declared length internally, closer to
                // that message-mode shape than to the reference's own
                // classic CCM, which streams through OpenSSL and only
                // forces a single call above this size).
                if *datalen > MAX_CCM_BUF {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                if buffer.len() + plain.len() > *datalen {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                buffer.extend_from_slice(plain);
                if buffer.len() == *datalen {
                    let ccm = AesCcm::new(key, *taglen)
                        .map_err(|_| CKR_DEVICE_ERROR)?;
                    let mut scratch = vec![0u8; buffer.len() + *taglen];
                    let n = ccm
                        .seal(nonce, aad, buffer, &mut scratch)
                        .map_err(|_| CKR_DEVICE_ERROR)?;
                    let ctlen = buffer.len();
                    cipher[..ctlen].copy_from_slice(&scratch[..ctlen]);
                    *tag = Some(scratch[ctlen..n].to_vec());
                    zeromem(&mut scratch);
                    zeromem(buffer);
                    buffer.clear();
                    *done = true;
                    return Ok(ctlen);
                }
                Ok(0)
            }
            ClassicMode::Gcm { buffer, .. } => {
                // Classic GCM has no declared total length to check
                // against (unlike CCM's `datalen`) and buffers the entire
                // message unconditionally (see the module-level doc
                // comment), so the cap has to be enforced directly on the
                // accumulated buffer here.
                if buffer.len() + plain.len() > MAX_CCM_BUF {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                buffer.extend_from_slice(plain);
                Ok(0)
            }
        }
    }

    /// `encrypt_final` dispatch for classic-mode operations. See
    /// `classic_encrypt_update` for the error-handling convention.
    fn classic_encrypt_final(
        classic: &mut ClassicMode,
        key: &[u8],
        cipher: &mut [u8],
        #[cfg(feature = "fips")] fips_approval: &mut FipsApproval,
    ) -> std::result::Result<usize, CK_RV> {
        match classic {
            ClassicMode::Block {
                cipher: bc,
                padded,
                block_aligned,
                buffer,
                blockctr,
                maxblocks,
            } => {
                if !*block_aligned {
                    if *maxblocks != 0 && *blockctr >= *maxblocks {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    return Ok(0);
                }
                if *padded {
                    // `BlockCipher::encrypt` conservatively requires
                    // `input.len() + 16` bytes of *output* space whenever
                    // padding is enabled, even though the actual PKCS#7
                    // padded output of a sub-block `buffer` is always
                    // exactly one block: use a fixed scratch buffer to
                    // satisfy that, then copy only the real output into
                    // the caller's (possibly smaller) `cipher` (mirrors
                    // the reference's own CTS 2-block scratch-buffer
                    // workaround for a similar API mismatch).
                    let mut scratch = [0u8; AES_BLOCK_SIZE * 2];
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result =
                        bc.encrypt(buffer.as_slice(), &mut scratch, true);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    let n = result.map_err(|_| CKR_DEVICE_ERROR)?;
                    if cipher.len() < n {
                        return Err(CKR_DEVICE_ERROR);
                    }
                    cipher[..n].copy_from_slice(&scratch[..n]);
                    zeromem(&mut scratch);
                    zeromem(buffer);
                    buffer.clear();
                    Ok(n)
                } else {
                    if !buffer.is_empty() {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    Ok(0)
                }
            }
            ClassicMode::Ccm {
                buffer, tag, done, ..
            } => {
                if !*done || !buffer.is_empty() {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                match tag.take() {
                    Some(mut t) => {
                        let n = t.len();
                        if cipher.len() < n {
                            return Err(CKR_DEVICE_ERROR);
                        }
                        cipher[..n].copy_from_slice(&t);
                        zeromem(&mut t);
                        Ok(n)
                    }
                    None => Err(CKR_GENERAL_ERROR),
                }
            }
            ClassicMode::Gcm {
                iv,
                aad,
                taglen,
                buffer,
            } => {
                let gcm =
                    AesGcm::new(key, *taglen).map_err(|_| CKR_DEVICE_ERROR)?;
                let needed = buffer.len() + *taglen;
                if cipher.len() < needed {
                    return Err(CKR_DEVICE_ERROR);
                }
                let n = gcm
                    .seal(iv, aad, buffer, cipher)
                    .map_err(|_| CKR_DEVICE_ERROR)?;
                zeromem(buffer);
                buffer.clear();
                Ok(n)
            }
        }
    }

    /// `decrypt_update` dispatch for classic-mode operations. See
    /// `classic_encrypt_update` for the error-handling convention.
    fn classic_decrypt_update(
        classic: &mut ClassicMode,
        key: &[u8],
        cipher_in: &[u8],
        plain: &mut [u8],
        #[cfg(feature = "fips")] fips_approval: &mut FipsApproval,
    ) -> std::result::Result<usize, CK_RV> {
        match classic {
            ClassicMode::Block {
                cipher: bc,
                padded,
                block_aligned,
                buffer,
                blockctr,
                maxblocks,
            } => {
                if !*block_aligned {
                    if *maxblocks != 0 {
                        let reqblocks = ((cipher_in.len() + AES_BLOCK_SIZE - 1)
                            / AES_BLOCK_SIZE)
                            as u128;
                        if *blockctr + reqblocks > *maxblocks {
                            return Err(CKR_DATA_LEN_RANGE);
                        }
                        *blockctr += reqblocks;
                    }
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result = bc
                        .decrypt(cipher_in, plain, false)
                        .map_err(|_| CKR_DEVICE_ERROR);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    return result;
                }
                if *padded {
                    buffer.extend_from_slice(cipher_in);
                    let total = buffer.len();
                    let release = if total == 0 {
                        0
                    } else {
                        ((total - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
                    };
                    if release == 0 {
                        return Ok(0);
                    }
                    let mut tmp = std::mem::take(buffer);
                    let remainder = tmp.split_off(release);
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result = bc.decrypt(&tmp, plain, false);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    let n = result.map_err(|_| CKR_DEVICE_ERROR)?;
                    zeromem(&mut tmp);
                    *buffer = remainder;
                    Ok(n)
                } else {
                    let total = buffer.len() + cipher_in.len();
                    let full = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                    if full == 0 {
                        buffer.extend_from_slice(cipher_in);
                        return Ok(0);
                    }
                    let take = full - buffer.len();
                    let mut tmp = Vec::with_capacity(full);
                    tmp.extend_from_slice(buffer);
                    tmp.extend_from_slice(&cipher_in[..take]);
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result = bc.decrypt(&tmp, plain, false);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    let n = result.map_err(|_| CKR_DEVICE_ERROR)?;
                    zeromem(&mut tmp);
                    buffer.clear();
                    buffer.extend_from_slice(&cipher_in[take..]);
                    Ok(n)
                }
            }
            ClassicMode::Ccm {
                nonce,
                aad,
                taglen,
                datalen,
                buffer,
                done,
                ..
            } => {
                if *done {
                    if !cipher_in.is_empty() {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    return Ok(0);
                }
                // See the matching check in `classic_encrypt_update`'s
                // Ccm arm: mirrors `crate::ossl::aes`'s `MAX_CCM_BUF`
                // check in `msg_decrypt_next`.
                if *datalen > MAX_CCM_BUF {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                let needlen = *datalen + *taglen;
                if buffer.len() + cipher_in.len() > needlen {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                buffer.extend_from_slice(cipher_in);
                if buffer.len() == needlen {
                    let (ct, tag) = buffer.split_at(*datalen);
                    let ccm = AesCcm::new(key, *taglen)
                        .map_err(|_| CKR_DEVICE_ERROR)?;
                    let n = ccm
                        .open(nonce, aad, ct, tag, plain)
                        .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?;
                    zeromem(buffer);
                    buffer.clear();
                    *done = true;
                    return Ok(n);
                }
                Ok(0)
            }
            ClassicMode::Gcm { buffer, .. } => {
                // See the matching check in `classic_encrypt_update`'s
                // Gcm arm.
                if buffer.len() + cipher_in.len() > MAX_CCM_BUF {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                buffer.extend_from_slice(cipher_in);
                Ok(0)
            }
        }
    }

    /// `decrypt_final` dispatch for classic-mode operations. See
    /// `classic_encrypt_update` for the error-handling convention.
    fn classic_decrypt_final(
        classic: &mut ClassicMode,
        key: &[u8],
        plain: &mut [u8],
        #[cfg(feature = "fips")] fips_approval: &mut FipsApproval,
    ) -> std::result::Result<usize, CK_RV> {
        match classic {
            ClassicMode::Block {
                cipher: bc,
                padded,
                block_aligned,
                buffer,
                blockctr,
                maxblocks,
            } => {
                if !*block_aligned {
                    if *maxblocks != 0 && *blockctr >= *maxblocks {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    return Ok(0);
                }
                if *padded {
                    if buffer.len() != AES_BLOCK_SIZE {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    // See classic_encrypt_final: BlockCipher::decrypt with
                    // padding needs input.len()+16 bytes of scratch space
                    // regardless of the real (<=16-byte) output.
                    let mut scratch = [0u8; AES_BLOCK_SIZE * 2];
                    #[cfg(feature = "fips")]
                    fips_approval.clear();
                    let result =
                        bc.decrypt(buffer.as_slice(), &mut scratch, true);
                    #[cfg(feature = "fips")]
                    fips_approval.update();
                    // `scratch` may hold genuine recovered plaintext even
                    // when `decrypt` goes on to report an invalid-padding
                    // error (padding validity is only checked once
                    // Update+Final have both already run) -- unlike
                    // `buffer`, which `ClassicMode`'s own `Drop` always
                    // zeroizes, this is a function-local scratch array
                    // with no such guarantee, so it must be scrubbed on
                    // every exit path here, not only on success.
                    let n = match result {
                        Ok(n) => n,
                        Err(_) => {
                            zeromem(&mut scratch);
                            return Err(CKR_ENCRYPTED_DATA_INVALID);
                        }
                    };
                    if plain.len() < n {
                        zeromem(&mut scratch);
                        return Err(CKR_DEVICE_ERROR);
                    }
                    plain[..n].copy_from_slice(&scratch[..n]);
                    zeromem(&mut scratch);
                    zeromem(buffer);
                    buffer.clear();
                    Ok(n)
                } else {
                    if !buffer.is_empty() {
                        return Err(CKR_DATA_LEN_RANGE);
                    }
                    Ok(0)
                }
            }
            ClassicMode::Ccm { buffer, done, .. } => {
                if !*done || !buffer.is_empty() {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                Ok(0)
            }
            ClassicMode::Gcm {
                iv,
                aad,
                taglen,
                buffer,
            } => {
                if buffer.len() < *taglen {
                    return Err(CKR_DATA_LEN_RANGE);
                }
                let ctlen = buffer.len() - *taglen;
                let (ct, tag) = buffer.split_at(ctlen);
                let gcm =
                    AesGcm::new(key, *taglen).map_err(|_| CKR_DEVICE_ERROR)?;
                if plain.len() < ctlen {
                    return Err(CKR_DEVICE_ERROR);
                }
                let n = gcm
                    .open(iv, aad, ct, tag, plain)
                    .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?;
                zeromem(buffer);
                buffer.clear();
                Ok(n)
            }
        }
    }

    /// Builds an `awslc::cipher::AesKeyWrap` key schedule from a
    /// PKCS#11 wrapping-key `Object`, scrubbing the raw key bytes on every
    /// path (mirroring `classic_new`'s `keybytes` handling above --
    /// `AesKeyWrap` itself scrubs its own internal key schedule on `Drop`,
    /// but the plain `Vec<u8>` this reads the key into first has no such
    /// guarantee).
    fn key_wrap_cipher(wrapping_key: &Object) -> Result<AesKeyWrap> {
        let mut kek = key_bytes(wrapping_key)?;
        if let Err(e) = crate::aes::check_key_len(kek.len()) {
            zeromem(&mut kek);
            return Err(e);
        }
        let result = AesKeyWrap::new(&kek).map_err(|_| CKR_DEVICE_ERROR);
        zeromem(&mut kek);
        Ok(result?)
    }

    /// Parses `mech.pParameter` as `CKM_AES_KEY_WRAP`/`_PKCS7`'s optional
    /// 8-byte custom IV: absent (`ulParameterLen == 0`) means "use RFC
    /// 3394's default", any other length is invalid -- reported as
    /// `bad_len_err`, since PKCS#11 wants different codes for the same
    /// malformed parameter depending on the API it came through:
    /// `CKR_MECHANISM_PARAM_INVALID` for `C_WrapKey`/`C_UnwrapKey` (`wrap`/
    /// `unwrap`'s own callers), `CKR_ARGUMENTS_BAD` for `C_EncryptInit`/
    /// `C_DecryptInit` (`key_wrap_classic_new`'s caller), matching how this
    /// same file's classic CBC/CBC-PAD IV-length check already uses
    /// `CKR_ARGUMENTS_BAD`.
    fn parse_kw_iv(
        mech: &CK_MECHANISM,
        bad_len_err: CK_RV,
    ) -> Result<Option<[u8; 8]>> {
        match mech.ulParameterLen {
            0 => Ok(None),
            8 => {
                let mut iv = [0u8; 8];
                iv.copy_from_slice(&bytes_to_vec(mech.pParameter, 8));
                Ok(Some(iv))
            }
            _ => Err(bad_len_err)?,
        }
    }

    /// Parses `mech.pParameter` as `CKM_AES_KEY_WRAP_KWP`'s optional 4-byte
    /// custom AIV prefix: absent (`ulParameterLen == 0`) means "use RFC
    /// 5649's default constant", any other length is invalid. See
    /// `parse_kw_iv`'s doc comment for why the error code is a parameter.
    fn parse_kwp_prefix(
        mech: &CK_MECHANISM,
        bad_len_err: CK_RV,
    ) -> Result<Option<[u8; 4]>> {
        match mech.ulParameterLen {
            0 => Ok(None),
            4 => {
                let mut prefix = [0u8; 4];
                prefix.copy_from_slice(&bytes_to_vec(mech.pParameter, 4));
                Ok(Some(prefix))
            }
            _ => Err(bad_len_err)?,
        }
    }

    /// Plain RFC 3394 wrap for `CKM_AES_KEY_WRAP`. `keydata` must already be
    /// a multiple of one semiblock (8 bytes); unlike PKCS7/KWP this
    /// mechanism does not pad. `iv` is the optional caller-supplied 8-byte
    /// IV from `mech.pParameter` (`None` uses RFC 3394's default).
    fn wrap_plain(
        kw: &AesKeyWrap,
        keydata: &[u8],
        iv: Option<&[u8; 8]>,
        output: &mut [u8],
    ) -> Result<usize> {
        if keydata.len() == 0 || keydata.len() % AES_KW_SEMIBLOCK != 0 {
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        let needed = keydata.len() + AES_KW_SEMIBLOCK;
        if output.len() == 0 {
            return Ok(needed);
        }
        if output.len() < needed {
            return Err(Error::buf_too_small(needed));
        }
        let n = kw
            .wrap_with_iv(iv, keydata, output)
            .map_err(|_| CKR_DATA_LEN_RANGE)?;
        Ok(n)
    }

    /// `CKM_AES_KEY_WRAP_PKCS7`: applies PKCS7 byte-padding to `keydata`
    /// itself (block size = one semiblock, 8 bytes -- always adds between 1
    /// and 8 padding bytes, a full pad block even when already
    /// semiblock-aligned, exactly as `crate::ossl::aes.rs`'s
    /// `encrypt_final` does for this mechanism), then wraps the padded
    /// buffer with plain (unpadded) RFC 3394 wrap -- this mechanism does
    /// *not* use KWP's alternative-IV encoding.
    fn wrap_pkcs7(
        kw: &AesKeyWrap,
        keydata: &mut Vec<u8>,
        iv: Option<&[u8; 8]>,
        output: &mut [u8],
    ) -> Result<usize> {
        if keydata.len() < AES_KW_SEMIBLOCK {
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        let pad = AES_KW_SEMIBLOCK - (keydata.len() % AES_KW_SEMIBLOCK);
        let padded_len = keydata.len() + pad;
        let needed = padded_len + AES_KW_SEMIBLOCK;
        if output.len() == 0 {
            return Ok(needed);
        }
        if output.len() < needed {
            return Err(Error::buf_too_small(needed));
        }
        keydata.resize(padded_len, pad as u8);
        let n = kw
            .wrap_with_iv(iv, keydata, output)
            .map_err(|_| CKR_DATA_LEN_RANGE)?;
        Ok(n)
    }

    /// `CKM_AES_KEY_WRAP_KWP`: RFC 5649 padded wrap, which handles
    /// arbitrary-length input itself via its alternative IV encoding.
    fn wrap_kwp(
        kw: &AesKeyWrap,
        keydata: &[u8],
        prefix: Option<[u8; 4]>,
        output: &mut [u8],
    ) -> Result<usize> {
        // Mirrors `crate::ossl::aes::AesOperation::encryption_len`'s
        // CKM_AES_KEY_WRAP_KWP formula so the buffer-size-query contract
        // (`output.len() == 0`) doesn't need a real output buffer.
        let needed = ((keydata.len() + AES_BLOCK_SIZE - 1) / AES_KW_SEMIBLOCK)
            * AES_KW_SEMIBLOCK;
        if output.len() == 0 {
            return Ok(needed);
        }
        if output.len() < needed {
            return Err(Error::buf_too_small(needed));
        }
        let n = match prefix {
            Some(p) => kw.wrap_padded_with_prefix(p, keydata, output),
            None => kw.wrap_padded(keydata, output),
        }
        .map_err(|_| CKR_DATA_LEN_RANGE)?;
        Ok(n)
    }

    /// Wraps `keydata` through a generic cipher mechanism (every mechanism
    /// `crate::aes::AES_MECHS` grants `CKF_WRAP` to besides the dedicated
    /// `CKM_AES_KEY_WRAP*` family: ECB/CBC/CBC-PAD/CTR/CTS and GCM/CCM),
    /// mirroring `crate::ossl::aes::AesOperation::wrap`'s own handling of
    /// these mechanisms via the exact same `encrypt_new`/`encrypt`/
    /// `encryption_len` this backend already implements for `C_Encrypt`.
    fn wrap_cipher(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        keydata: &mut Vec<u8>,
        output: &mut [u8],
    ) -> Result<usize> {
        let mut op = Self::encrypt_new(mech, wrapping_key)?;
        match mech.mechanism {
            CKM_AES_CBC | CKM_AES_ECB => {
                /* Non-padding block modes need zero padding for the input. */
                let pad = keydata.len() % AES_BLOCK_SIZE;
                if pad != 0 {
                    keydata.resize(keydata.len() + AES_BLOCK_SIZE - pad, 0);
                }
            }
            CKM_AES_CCM => {
                /* AWS-LC's one-shot AesCcm has no way to report a
                 * data-length mismatch itself before the real `seal` call,
                 * so check it here, matching the reference. */
                let datalen = match &op.classic {
                    Some(ClassicMode::Ccm { datalen, .. }) => *datalen,
                    _ => unreachable!(),
                };
                if datalen != keydata.len() {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
            }
            _ => (),
        }
        let needed_len = op.encryption_len(keydata.len(), true)?;
        if output.len() == 0 {
            return Ok(needed_len);
        }
        if output.len() < needed_len {
            return Err(Error::buf_too_small(needed_len));
        }
        op.encrypt(keydata, output)
    }

    /// Unwraps `data` through a generic cipher mechanism. See
    /// `wrap_cipher`'s doc comment.
    fn unwrap_cipher(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key)?;
        // `result` can hold partially- or fully-written (in the AEAD
        // cases, potentially still-unauthenticated) key material even
        // when `decrypt` ultimately errors -- a `SecretBuf` scrubs it on
        // every exit path automatically (including this one, via `?`),
        // unlike a plain `Vec<u8>` which would need an explicit
        // `zeromem()` on each fallible path (see `unwrap_plain`'s/
        // `unwrap_kwp`'s/`unwrap_pkcs7`'s own hand-rolled version of the
        // same thing).
        let mut result = SecretBuf::zeroed(data.len());
        let outlen = op.decrypt(data, &mut result)?;
        result.truncate(outlen);
        Ok(result.into_vec())
    }

    /// Instantiates a new AES Key-Wrap operation and performs the wrap in
    /// one shot, mirroring `crate::ossl::aes::AesOperation::wrap`'s
    /// signature and its buffer-size-query contract (`output.len() == 0`
    /// returns the needed length without consuming `keydata`).
    ///
    /// Unlike the OpenSSL backend -- which treats `CKM_AES_KEY_WRAP*` as
    /// "just another `EncAlg`" dispatched through the very same
    /// `encrypt_new`/`encrypt` machinery as CBC/GCM/CCM (see
    /// `EncAlg::AesWrap`/`AesWrapPad` in `src/ossl/aes.rs`) -- this
    /// backend's `awslc::cipher::AesKeyWrap` is a distinct primitive with
    /// its own key schedule, not a `BlockCipher`/AEAD shape,
    /// so key-wrap does not reuse `ClassicMode`/`classic_new` here. Per the
    /// reference (`src/ossl/aes.rs:685-822` plus its `encrypt_update`/
    /// `encrypt_final`/`encryption_len` KEY_WRAP arms): `CKM_AES_KEY_WRAP`
    /// and `CKM_AES_KEY_WRAP_PKCS7` both use plain (unpadded) RFC 3394
    /// wrap, with PKCS7 applying its own byte-padding to the plaintext
    /// first; `CKM_AES_KEY_WRAP_KWP` uses RFC 5649's padded wrap directly.
    ///
    /// A custom initial value (`mech.pParameter`) is supported for all
    /// three mechanisms, matching the reference: an 8-byte IV for
    /// `CKM_AES_KEY_WRAP`/`_PKCS7` (RFC 3394's own `AES_wrap_key` IV
    /// parameter), and a 4-byte AIV prefix for `CKM_AES_KEY_WRAP_KWP`
    /// (RFC 5649's customizable constant, replacing its fixed default --
    /// the AIV's other 4 bytes always carry the real data length, which
    /// isn't customizable).
    pub fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
    ) -> Result<usize> {
        let kw = match Self::key_wrap_cipher(wrapping_key) {
            Ok(kw) => kw,
            Err(e) => {
                zeromem(&mut keydata);
                return Err(e);
            }
        };
        let result = match mech.mechanism {
            CKM_AES_KEY_WRAP => {
                match Self::parse_kw_iv(mech, CKR_MECHANISM_PARAM_INVALID) {
                    Ok(iv) => {
                        Self::wrap_plain(&kw, &keydata, iv.as_ref(), output)
                    }
                    Err(e) => Err(e),
                }
            }
            CKM_AES_KEY_WRAP_PKCS7 => {
                match Self::parse_kw_iv(mech, CKR_MECHANISM_PARAM_INVALID) {
                    Ok(iv) => {
                        Self::wrap_pkcs7(&kw, &mut keydata, iv.as_ref(), output)
                    }
                    Err(e) => Err(e),
                }
            }
            CKM_AES_KEY_WRAP_KWP => {
                match Self::parse_kwp_prefix(mech, CKR_MECHANISM_PARAM_INVALID)
                {
                    Ok(prefix) => Self::wrap_kwp(&kw, &keydata, prefix, output),
                    Err(e) => Err(e),
                }
            }
            // Every mechanism the shared `crate::aes::AES_MECHS` table
            // grants CKF_WRAP to besides the CKM_AES_KEY_WRAP* family
            // lands here (ECB/CBC/CBC-PAD/CTR/CTS and GCM/CCM: see
            // `AES_MECHS[0]`/`[1]` in `src/aes.rs`, which this module's
            // `register_mechanisms` reuses for both backends), matching
            // the reference `crate::ossl::aes::AesOperation::wrap`, which
            // treats these mechanisms identically whether reached through
            // `C_WrapKey` or `C_Encrypt`: `encrypt_new` already implements
            // every one of them (rejecting `CKM_AES_CTS` itself, same as
            // the reference), so this just reuses that machinery --
            // zero-padding to a block boundary for the two non-padding
            // block modes first, since `encrypt`/`encryption_len` require
            // exact block-multiple input for those (`ClassicMode::Block`'s
            // `padded: false` arm), and checking CCM's configured data
            // length against `keydata` up front, since AWS-LC's one-shot
            // `AesCcm` has no way to report that mismatch itself before
            // the real `seal` call.
            _ => Self::wrap_cipher(mech, wrapping_key, &mut keydata, output),
        };
        zeromem(&mut keydata);
        result
    }

    /// Plain RFC 3394 unwrap for `CKM_AES_KEY_WRAP`. The smallest valid
    /// wrapped blob is 24 bytes (a 16-byte minimum plaintext plus the
    /// 8-byte integrity/IV overhead), and both wrapped and unwrapped
    /// lengths are always multiples of one semiblock.
    fn unwrap_plain(
        kw: &AesKeyWrap,
        data: &[u8],
        iv: Option<&[u8; 8]>,
    ) -> Result<Vec<u8>> {
        if data.len() % AES_KW_SEMIBLOCK != 0
            || data.len() < AES_KW_SEMIBLOCK * 3
        {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE)?;
        }
        let mut out = vec![0u8; data.len() - AES_KW_SEMIBLOCK];
        match kw.unwrap_with_iv(iv, data, &mut out) {
            Ok(n) => {
                out.truncate(n);
                Ok(out)
            }
            Err(_) => {
                zeromem(&mut out);
                Err(CKR_ENCRYPTED_DATA_INVALID)?
            }
        }
    }

    /// RFC 5649 padded unwrap for `CKM_AES_KEY_WRAP_KWP`.
    fn unwrap_kwp(
        kw: &AesKeyWrap,
        data: &[u8],
        prefix: Option<[u8; 4]>,
    ) -> Result<Vec<u8>> {
        if data.len() % AES_KW_SEMIBLOCK != 0 || data.len() < AES_BLOCK_SIZE {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE)?;
        }
        let mut out = vec![0u8; data.len()];
        let result = match prefix {
            Some(p) => kw.unwrap_padded_with_prefix(p, data, &mut out),
            None => kw.unwrap_padded(data, &mut out),
        };
        match result {
            Ok(n) => {
                out.truncate(n);
                Ok(out)
            }
            Err(_) => {
                zeromem(&mut out);
                Err(CKR_ENCRYPTED_DATA_INVALID)?
            }
        }
    }

    /// `CKM_AES_KEY_WRAP_PKCS7` unwrap: plain (unpadded) RFC 3394 unwrap
    /// first, then strips the PKCS7 byte-padding from the recovered
    /// plaintext, mirroring `crate::ossl::aes::AesOperation::decrypt_final`'s
    /// KEY_WRAP_PKCS7 arm -- including its constant-time padding check
    /// (evaluates all 8 candidate pad lengths unconditionally rather than
    /// branching on the padding byte's value, which is attacker-influenced
    /// since it comes from data just authenticated by the wrap integrity
    /// check but is not itself independently trusted length metadata).
    fn unwrap_pkcs7(
        kw: &AesKeyWrap,
        data: &[u8],
        iv: Option<&[u8; 8]>,
    ) -> Result<Vec<u8>> {
        if data.len() % AES_KW_SEMIBLOCK != 0
            || data.len() < AES_KW_SEMIBLOCK * 3
        {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE)?;
        }
        let mut unwrapped = vec![0u8; data.len() - AES_KW_SEMIBLOCK];
        let n = match kw.unwrap_with_iv(iv, data, &mut unwrapped) {
            Ok(n) => n,
            Err(_) => {
                zeromem(&mut unwrapped);
                return Err(CKR_ENCRYPTED_DATA_INVALID)?;
            }
        };
        unwrapped.truncate(n);

        if unwrapped.len() < AES_BLOCK_SIZE
            || unwrapped.len() % AES_KW_SEMIBLOCK != 0
        {
            zeromem(&mut unwrapped);
            return Err(CKR_ENCRYPTED_DATA_INVALID)?;
        }

        let n = unwrapped.len();
        let tail = &unwrapped[n - AES_KW_SEMIBLOCK..];
        let mut pad_len = 0usize;
        let mut valid = 0usize;
        for k in 1..=AES_KW_SEMIBLOCK {
            let expected = [k as u8; AES_KW_SEMIBLOCK];
            let matches =
                constant_time_eq(&tail[AES_KW_SEMIBLOCK - k..], &expected[..k])
                    as usize;
            pad_len |= k * matches;
            valid |= matches;
        }
        if valid != 1 {
            zeromem(&mut unwrapped);
            return Err(CKR_ENCRYPTED_DATA_INVALID)?;
        }

        let plain_len = n - pad_len;
        let result = unwrapped[..plain_len].to_vec();
        zeromem(&mut unwrapped);
        Ok(result)
    }

    /// Instantiates a new AES Key-Unwrap operation and performs the unwrap
    /// in one shot. See `wrap`'s doc comment for the structural rationale
    /// (a distinct `AesKeyWrap` primitive rather than `ClassicMode`) and
    /// custom-IV support.
    pub fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let kw = Self::key_wrap_cipher(wrapping_key)?;
        match mech.mechanism {
            CKM_AES_KEY_WRAP => Self::unwrap_plain(
                &kw,
                data,
                Self::parse_kw_iv(mech, CKR_MECHANISM_PARAM_INVALID)?.as_ref(),
            ),
            CKM_AES_KEY_WRAP_PKCS7 => Self::unwrap_pkcs7(
                &kw,
                data,
                Self::parse_kw_iv(mech, CKR_MECHANISM_PARAM_INVALID)?.as_ref(),
            ),
            CKM_AES_KEY_WRAP_KWP => Self::unwrap_kwp(
                &kw,
                data,
                Self::parse_kwp_prefix(mech, CKR_MECHANISM_PARAM_INVALID)?,
            ),
            // Mirrors `wrap`'s own fallback arm above: CBC/ECB/CTR/CTS and
            // GCM/CCM also carry CKF_UNWRAP in the shared mechanism-info
            // table -- see `wrap_cipher`'s doc comment.
            _ => Self::unwrap_cipher(mech, wrapping_key, data),
        }
    }

    /// Used by `AesMechanism::msg_encryption_op` (`src/aes.rs`). Only the
    /// two mechanisms `crate::aes::AES_MECHS[1]` actually grants
    /// `CKF_MESSAGE_ENCRYPT`/`CKF_MESSAGE_DECRYPT` to (see
    /// `register_mechanisms` above) can ever reach here: PKCS#11's
    /// message-based encrypt/decrypt API is AEAD-specific (its only
    /// defined per-message parameter structs are `CK_GCM_MESSAGE_PARAMS`
    /// and `CK_CCM_MESSAGE_PARAMS` -- confirmed by `src/ossl/aes.rs`'s own
    /// `impl MsgEncryption`/`impl MsgDecryption for AesOperation`, which
    /// likewise only ever matches `CKM_AES_GCM`/`CKM_AES_CCM` and falls
    /// through to `CKR_GENERAL_ERROR` for anything else); the classic
    /// block-cipher-family mechanisms (ECB/CBC/CBC-PAD/CTR/OFB/CFB*) carry
    /// no message flags at all and are rejected by
    /// `AesMechanism::msg_encryption_op`/`msg_decryption_op`
    /// (`src/aes.rs`) before ever calling this function.
    pub fn msg_encrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        match mech.mechanism {
            CKM_AES_GCM | CKM_AES_CCM => (),
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }
        // Matches `classic_new`'s and `AesCmacOperation::init`'s own
        // key-length validation at init time: without this, a bad-length
        // key isn't caught until the first `msg_encrypt` call, where it
        // fails deep inside `AesGcm::new`/`AesCcm::new` with a less
        // specific error than CKR_KEY_SIZE_RANGE.
        let keybytes = SecretBuf::from_vec(key_bytes(key)?);
        crate::aes::check_key_len(keybytes.len())?;
        Ok(AesOperation {
            mech: mech.mechanism,
            key: keybytes,
            finalized: false,
            classic: None,
            encrypting: true,
            in_use: false,
            // No per-message parameters are available yet (message mode's
            // `CK_MECHANISM` carries none for `CKM_AES_GCM`/`CKM_AES_CCM`
            // -- they arrive later, per-message, in `msg_encrypt_gcm`/
            // `msg_encrypt_ccm`'s own `param`/`paramlen`), matching
            // `crate::ossl::aes::AesOperation::msg_encrypt_init`, which
            // likewise seeds `params.iv` from a dummy, parameter-less
            // `CK_MECHANISM` at this same point.
            msg_iv: None,
            key_wrap: None,
            msg_buffer: Vec::new(),
            msg_aad: Vec::new(),
            msg_tag_len: None,
            msg_ccm_data_len: None,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// Used by `AesMechanism::msg_decryption_op` (`src/aes.rs`). See
    /// `msg_encrypt_init`'s doc comment for why only GCM/CCM are accepted
    /// and why the key length is checked here too.
    pub fn msg_decrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        match mech.mechanism {
            CKM_AES_GCM | CKM_AES_CCM => (),
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }
        let keybytes = SecretBuf::from_vec(key_bytes(key)?);
        crate::aes::check_key_len(keybytes.len())?;
        Ok(AesOperation {
            mech: mech.mechanism,
            key: keybytes,
            finalized: false,
            classic: None,
            encrypting: false,
            in_use: false,
            // See msg_encrypt_init's doc comment for why this starts `None`.
            msg_iv: None,
            key_wrap: None,
            msg_buffer: Vec::new(),
            msg_aad: Vec::new(),
            msg_tag_len: None,
            msg_ccm_data_len: None,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// Internal helper for dealing with fatal `msg_encrypt`/`msg_decrypt`
    /// errors: finalizes the operation before returning the error, mirroring
    /// `src/ossl/aes.rs`'s own `op_err` helper and matching the
    /// `MsgEncryption`/`MsgDecryption` trait contract (every error finalizes
    /// the operation except `CKR_BUFFER_TOO_SMALL`, which must NOT go
    /// through this helper).
    fn op_err(&mut self, rv: CK_RV) -> Error {
        self.finalized = true;
        Error::ck_rv(rv)
    }
}

// No `impl Drop for AesOperation` needed: `key: SecretBuf` (rather than a
// plain `Vec<u8>`) scrubs itself automatically when `AesOperation` is
// dropped, on every exit path (success, error, or panic) -- including
// every fallible step inside `classic_new`/`msg_encrypt_init`/`msg_
// decrypt_init` that builds `keybytes` before it's ever assigned into a
// live `AesOperation`, since a `SecretBuf` scrubs itself the moment IT
// drops, not just when its eventual owner does.

impl MechOperation for AesOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
}

impl MessageOperation for AesOperation {
    /// `self.in_use` doubles as the message-mode "a `Begin` has run but its
    /// matching `Final` hasn't yet" flag, the same field classic-mode's
    /// `encrypt_update`/`decrypt_update` use for their own "at least one
    /// update has run" tracking -- a given `AesOperation` is constructed as
    /// exactly one of classic-mode, key-wrap, or message-mode (never more
    /// than one), so the two uses never overlap on the same instance.
    fn busy(&self) -> bool {
        self.in_use
    }

    /// Ends the message-mode bracket (`C_MessageEncryptFinal`/
    /// `C_MessageDecryptFinal`). A successful `msg_encrypt`/`msg_decrypt`
    /// (or a completed `Begin`/`Next`/`Final` sequence) does NOT itself set
    /// `self.finalized` -- PKCS#11 allows several real messages under one
    /// `C_MessageEncryptInit`/`C_MessageEncryptFinal` bracket (see
    /// `msg_encrypt_gcm`'s counter/maxcount carry-forward, which exists
    /// for exactly that multi-message case), and `dyn ManageOperation`'s
    /// `get_op` (`src/session.rs`) refuses to hand out an already-
    /// `finalized` operation -- so eagerly finalizing here would make
    /// this very function (and any subsequent real message in the same
    /// bracket) unreachable. `finalized` is instead only ever set by a
    /// fatal error (`op_err`) or by this explicit `finalize()`, matching
    /// `crate::ossl::aes::AesOperation::finalize`'s role -- including its
    /// `in_use` check, rejecting an attempt to end the bracket while a
    /// `Begin`/`Next`/`Final` message is still in progress. Overriding the
    /// `MessageOperation` default (which unconditionally returns
    /// `CKR_OPERATION_NOT_INITIALIZED`) is required for
    /// `C_MessageEncryptFinal`/`C_MessageDecryptFinal` to ever succeed on
    /// this backend.
    fn finalize(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }
        self.finalized = true;
        Ok(())
    }
}

impl AesOperation {
    /// GCM one-shot message encryption, factored out of `MsgEncryption::
    /// msg_encrypt` so that trait method can dispatch on `self.mech`
    /// between this and [`Self::msg_encrypt_ccm`] -- the only two
    /// mechanisms message mode supports (see `msg_encrypt_init`'s doc
    /// comment). Supports the full IV-generator set (`CKG_NO_GENERATE`,
    /// `CKG_GENERATE_RANDOM`, `CKG_GENERATE`, `CKG_GENERATE_COUNTER`,
    /// `CKG_GENERATE_COUNTER_XOR`) and non-zero `ulIvFixedBits`, mirroring
    /// `crate::ossl::aes::AesOperation::init_msg_params`'s `CKM_AES_GCM`
    /// arm: bounds-checks `ulIvFixedBits` against `ulIvLen * 8`, enforces
    /// the minimum-random-bits rule for `CKG_GENERATE_RANDOM`, enforces
    /// non-zero generated bits for any generator other than
    /// `CKG_NO_GENERATE`, then drives the actual IV bytes through
    /// [`generate_iv`] (writing the result back into the caller's `pIv`
    /// buffer for every generator except `CKG_NO_GENERATE`, which keeps
    /// the caller-supplied IV as-is).
    /// Parses+validates a `CK_GCM_MESSAGE_PARAMS` and establishes this
    /// operation's IV in `self.msg_iv` (generating one if requested,
    /// writing it back to the caller's `pIv` buffer) -- the setup half of
    /// [`Self::msg_encrypt_gcm`], factored out so `msg_encrypt_begin`'s GCM
    /// path can reuse the exact same validation/generation rules without
    /// duplicating them. Returns the tag length in bytes and the raw tag
    /// pointer. See `msg_encrypt_gcm`'s original doc comment (preserved
    /// here) for the full rationale of each check.
    ///
    /// Supports the full IV-generator set (`CKG_NO_GENERATE`,
    /// `CKG_GENERATE_RANDOM`, `CKG_GENERATE`, `CKG_GENERATE_COUNTER`,
    /// `CKG_GENERATE_COUNTER_XOR`) and non-zero `ulIvFixedBits`, mirroring
    /// `crate::ossl::aes::AesOperation::init_msg_params`'s `CKM_AES_GCM`
    /// arm: bounds-checks `ulIvFixedBits` against `ulIvLen * 8`, enforces
    /// the minimum-random-bits rule for `CKG_GENERATE_RANDOM`, enforces
    /// non-zero generated bits for any generator other than
    /// `CKG_NO_GENERATE`, then drives the actual IV bytes through
    /// [`generate_iv`] (writing the result back into the caller's `pIv`
    /// buffer for every generator except `CKG_NO_GENERATE`, which keeps
    /// the caller-supplied IV as-is).
    fn setup_msg_encrypt_gcm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
    ) -> Result<(usize, CK_BYTE_PTR)> {
        // None of the pure parameter validation below finalizes the
        // operation on error -- matching the reference backend's own
        // `init_msg_params`, which uses plain `Err(...)?` throughout its
        // GCM arm. This runs before `self.in_use` is set (by the caller,
        // once this function returns `Ok`), so a validation failure here
        // must leave the operation exactly as it was before this call --
        // callers like `C_EncryptMessageBegin` are allowed to retry with
        // corrected parameters within the same bracket.
        let params = match read_gcm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        // `pTag` is not read here -- only at Final, when the sealed tag is
        // written out -- so it is not validated at Begin time, matching
        // the reference backend's own `init_msg_params` (which only
        // null-checks `pIv` here; an invalid tag length below is reported
        // as CKR_MECHANISM_PARAM_INVALID, not CKR_ARGUMENTS_BAD).
        if params.pIv.is_null() {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        if params.ulTagBits < 8 || params.ulTagBits > 128 {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        let tag_len = match usize::try_from(params.ulTagBits) {
            Ok(v) => (v + 7) / 8,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let iv_len = match usize::try_from(params.ulIvLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        if iv_len == 0 {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        if params.ulIvFixedBits > params.ulIvLen * 8 {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        let ivfixedbits = match usize::try_from(params.ulIvFixedBits) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        if params.ivGenerator == CKG_GENERATE_RANDOM
            && iv_len * 8 - ivfixedbits < MIN_RANDOM_IV_BITS
        {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        if params.ivGenerator != CKG_NO_GENERATE
            && iv_len * 8 - ivfixedbits == 0
        {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }

        // A counter-based generator's counter/maxcount must survive
        // across multiple real messages processed under one
        // `C_MessageEncryptInit`/`C_MessageEncryptFinal` bracket (PKCS#11
        // allows several `C_EncryptMessage` calls per bracket), matching
        // `crate::ossl::aes::AesOperation::init_msg_params`'s own
        // `counter: self.params.iv.counter, maxcount: self.params.iv.
        // maxcount` carry-forward; a fresh operation (or one that has
        // never generated an IV) starts both at 0.
        let (prev_counter, prev_maxcount) = match &self.msg_iv {
            Some(prev) => (prev.counter, prev.maxcount),
            None => (0, 0),
        };
        self.msg_iv = Some(AesIvData {
            buf: bytes_to_vec(params.pIv, iv_len),
            fixedbits: ivfixedbits,
            generator: params.ivGenerator,
            counter: prev_counter,
            maxcount: prev_maxcount,
        });
        if params.ivGenerator != CKG_NO_GENERATE {
            // Deliberate exception to this function's own "pure validation
            // never finalizes" rule stated above: an RNG failure here isn't
            // a caller-correctable parameter error like the checks above,
            // it's the DRBG itself refusing to produce output, so retrying
            // Begin with the same or different parameters is no more likely
            // to succeed. Finalizing (via op_err) is safer than leaving an
            // operation half-populated with a msg_iv whose IV was never
            // actually written. The reference backend's equivalent path
            // does not finalize here; this is not a bug carried over from
            // it, but an intentional divergence.
            if let Err(e) = generate_iv(self.msg_iv.as_mut().unwrap()) {
                return Err(self.op_err(e.rv()));
            }
            let iv_out = self.msg_iv.as_ref().unwrap().buf.clone();
            // SAFETY: params.pIv is the caller-supplied CK_GCM_MESSAGE_
            // PARAMS::pIv pointer, already read from (and therefore known
            // valid for iv_out.len() bytes) earlier in this function.
            unsafe {
                crate::lowlevel::cipher::write_out(params.pIv, &iv_out);
            }
        }
        Ok((tag_len, params.pTag))
    }

    fn msg_encrypt_gcm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        let (tag_len, tag_ptr) = self.setup_msg_encrypt_gcm(param, paramlen)?;
        let iv = self.msg_iv.as_ref().unwrap().buf.clone();

        if cipher.len() < plain.len() {
            // The only non-fatal error: does not finalize the operation,
            // so the caller can retry with a correctly-sized buffer.
            return Err(Error::buf_too_small(plain.len()));
        }

        let gcm = match AesGcm::new(&self.key, tag_len) {
            Ok(g) => g,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        let mut sealed = vec![0u8; plain.len() + tag_len];
        let n = match gcm.seal(&iv, adata, plain, &mut sealed) {
            Ok(n) => n,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        cipher[..plain.len()].copy_from_slice(&sealed[..plain.len()]);
        // SAFETY: tag_ptr is CK_GCM_MESSAGE_PARAMS::pTag; write_out is a
        // no-op if it's null (not validated non-null by
        // setup_msg_encrypt_gcm, which only reads it at Final), and
        // otherwise it points at a caller-owned buffer sized for the
        // ulTagBits this same params struct declared.
        unsafe {
            crate::lowlevel::cipher::write_out(
                tag_ptr,
                &sealed[plain.len()..n],
            );
        }

        // AEAD FIPS approval is determined explicitly from the IV/tag
        // properties, not the generic `clear()`/`update()` service-
        // indicator bracket: AWS-LC's indicator counter only ever moves
        // for AEAD *open* (decrypt), never *seal* (encrypt), so bracketing
        // `gcm.seal()` above would see no counter movement and
        // `update()`'s one-way ratchet would permanently record this as
        // unapproved even when the IV/tag are FIPS-compliant. See
        // `init_classic_mode`'s identical reasoning for the classic-mode
        // GCM/CCM case, and `crate::fips::awslc_fips_tests` for the
        // AWS-LC service-indicator behavior this is based on.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_ENCRYPT,
            tag_len,
        )?;

        Ok(plain.len())
    }

    /// CCM one-shot message encryption, mirroring
    /// `crate::ossl::aes::AesOperation::init_msg_params`'s `CKM_AES_CCM`
    /// arm (nonce-length/data-length/tag-length validation and nonce
    /// generator policy) plus its `msg_encrypt_final`'s CCM branch (the
    /// `ulDataLen == plain.len()` check -- message mode's one-shot
    /// `msg_encrypt` is exactly the reference's `msg_encrypt_begin` +
    /// `msg_encrypt_final` with an empty intermediate buffer, so
    /// `self.buffer.len()` there is always 0 here). Supports the full
    /// nonce-generator set, same as [`Self::msg_encrypt_gcm`] -- CCM has
    /// the identical restriction to lift here (see that function's doc
    /// comment for the shared validation rules).
    /// The CCM analogue of [`Self::setup_msg_encrypt_gcm`]: parses+
    /// validates a `CK_CCM_MESSAGE_PARAMS` and establishes this
    /// operation's nonce in `self.msg_iv`, returning the tag length in
    /// bytes, the raw MAC pointer, and the declared total data length
    /// (`ulDataLen`) -- the caller is responsible for checking the actual
    /// plaintext length against that declared length, since `Begin` (which
    /// has no plaintext yet) and one-shot `msg_encrypt`/`msg_encrypt_final`
    /// (which do) need to do that at different points.
    fn setup_msg_encrypt_ccm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
    ) -> Result<(usize, CK_BYTE_PTR, usize)> {
        // See setup_msg_encrypt_gcm's doc comment: none of this pure
        // parameter validation finalizes the operation on error.
        let params = match read_ccm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        if params.pNonce.is_null() || params.pMAC.is_null() {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        let max_data_len = match ccm_max_data_len(params.ulNonceLen) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if params.ulDataLen > max_data_len
            || params.ulDataLen > (CK_ULONG::MAX - params.ulMACLen)
        {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        match params.ulMACLen {
            4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
            _ => return Err(Error::ck_rv(CKR_ARGUMENTS_BAD)),
        }
        let tag_len = match usize::try_from(params.ulMACLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let nonce_len = match usize::try_from(params.ulNonceLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let data_len = match usize::try_from(params.ulDataLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        // Mirrors classic-mode CCM's own MAX_CCM_BUF check (see
        // classic_encrypt_update's doc comment): this backend buffers the
        // whole declared length internally for message-mode CCM too, so an
        // unbounded ulDataLen would let a caller grow msg_buffer without
        // limit across repeated Next calls.
        if data_len > MAX_CCM_BUF {
            return Err(Error::ck_rv(CKR_DATA_LEN_RANGE));
        }
        if params.ulNonceFixedBits > params.ulNonceLen * 8 {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        let fixed_bits = match usize::try_from(params.ulNonceFixedBits) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        if params.nonceGenerator == CKG_GENERATE_RANDOM
            && nonce_len * 8 - fixed_bits < MIN_RANDOM_IV_BITS
        {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        if params.nonceGenerator != CKG_NO_GENERATE
            && nonce_len * 8 - fixed_bits == 0
        {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }

        // See msg_encrypt_gcm's doc comment for why the counter/maxcount
        // carry forward from any prior message in this bracket.
        let (prev_counter, prev_maxcount) = match &self.msg_iv {
            Some(prev) => (prev.counter, prev.maxcount),
            None => (0, 0),
        };
        self.msg_iv = Some(AesIvData {
            buf: bytes_to_vec(params.pNonce, nonce_len),
            fixedbits: fixed_bits,
            generator: params.nonceGenerator,
            counter: prev_counter,
            maxcount: prev_maxcount,
        });
        if params.nonceGenerator != CKG_NO_GENERATE {
            // See msg_encrypt_gcm's/setup_msg_encrypt_gcm's matching
            // comment: an RNG failure here deliberately finalizes, unlike
            // the pure-validation checks above, since it is not
            // caller-correctable and leaving a half-populated msg_iv around
            // is worse than ending the operation.
            if let Err(e) = generate_iv(self.msg_iv.as_mut().unwrap()) {
                return Err(self.op_err(e.rv()));
            }
            let nonce_out = self.msg_iv.as_ref().unwrap().buf.clone();
            // SAFETY: params.pNonce is the caller-supplied
            // CK_CCM_MESSAGE_PARAMS::pNonce pointer, already read from
            // (and therefore known valid for nonce_out.len() bytes)
            // earlier in this function.
            unsafe {
                crate::lowlevel::cipher::write_out(params.pNonce, &nonce_out);
            }
        }
        Ok((tag_len, params.pMAC, data_len))
    }

    fn msg_encrypt_ccm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        let (tag_len, mac_ptr, data_len) =
            self.setup_msg_encrypt_ccm(param, paramlen)?;
        if plain.len() != data_len {
            return Err(self.op_err(CKR_DATA_LEN_RANGE));
        }
        let nonce = self.msg_iv.as_ref().unwrap().buf.clone();

        if cipher.len() < plain.len() {
            // The only non-fatal error: does not finalize the operation,
            // so the caller can retry with a correctly-sized buffer.
            return Err(Error::buf_too_small(plain.len()));
        }

        let ccm = match AesCcm::new(&self.key, tag_len) {
            Ok(c) => c,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        let mut sealed = vec![0u8; plain.len() + tag_len];
        let n = match ccm.seal(&nonce, adata, plain, &mut sealed) {
            Ok(n) => n,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        cipher[..plain.len()].copy_from_slice(&sealed[..plain.len()]);
        // SAFETY: mac_ptr is CK_CCM_MESSAGE_PARAMS::pMAC, validated
        // non-null and sized for tag_len bytes by setup_msg_encrypt_ccm.
        unsafe {
            crate::lowlevel::cipher::write_out(
                mac_ptr,
                &sealed[plain.len()..n],
            );
        }

        // See msg_encrypt_gcm's doc comment for why FIPS approval for
        // AEAD is determined explicitly here rather than through the
        // generic clear()/update() bracket.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_ENCRYPT,
            tag_len,
        )?;

        Ok(plain.len())
    }

    /// GCM one-shot message decryption, factored out of `MsgDecryption::
    /// msg_decrypt` for the same reason as [`Self::msg_encrypt_gcm`]. The
    /// IV and tag are always caller-supplied here (`src/encryption.rs`'s
    /// `aes_gcm_decrypt` always passes `CKG_NO_GENERATE`), so no
    /// generation logic is needed on this side -- matching
    /// `src/ossl/aes.rs`'s own decrypt path, which forces the generator
    /// to `CKG_NO_GENERATE` regardless of what's passed in.
    /// Parses+validates a `CK_GCM_MESSAGE_PARAMS` and establishes this
    /// operation's (always caller-supplied, never generated) IV in
    /// `self.msg_iv` -- the setup half of [`Self::msg_decrypt_gcm`],
    /// factored out so `msg_decrypt_begin`'s GCM path can reuse it.
    /// Returns the tag length in bytes only: unlike the encrypt side, the
    /// actual tag *bytes* aren't read here, since for a `Begin`/`Next`/
    /// `Final` decrypt the tag only becomes meaningful once the whole
    /// ciphertext has arrived (`Final`) -- so `msg_decrypt_gcm`/
    /// `msg_decrypt_final` each re-parse `param` themselves, right at the
    /// point they actually call `open()`.
    fn setup_msg_decrypt_gcm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
    ) -> Result<usize> {
        // See setup_msg_encrypt_gcm's doc comment: none of this pure
        // parameter validation finalizes the operation on error.
        let params = match read_gcm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        // `pTag` is not validated here -- see this function's doc comment
        // for why -- matching the reference backend's `init_msg_params`,
        // which only null-checks `pIv`; an invalid tag length below is
        // reported as CKR_MECHANISM_PARAM_INVALID, not CKR_ARGUMENTS_BAD.
        if params.pIv.is_null() {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        if params.ulTagBits < 8 || params.ulTagBits > 128 {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        let tag_len = match usize::try_from(params.ulTagBits) {
            Ok(v) => (v + 7) / 8,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let iv_len = match usize::try_from(params.ulIvLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        if iv_len == 0 {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        let iv = bytes_to_vec(params.pIv, iv_len);

        // Decrypt always uses the caller-supplied IV verbatim: PKCS#11's
        // generator/fixed-bits fields only govern encrypt-side generation
        // (matching crate::ossl::aes::init_msg_params's own `else` arm,
        // which forces CKG_NO_GENERATE on the decrypt side regardless of
        // what the caller passed in).
        self.msg_iv = Some(AesIvData {
            buf: iv,
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        });
        Ok(tag_len)
    }

    fn msg_decrypt_gcm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.setup_msg_decrypt_gcm(param, paramlen)?;
        // Re-parse to read the tag bytes: cheap (no side effects) and
        // avoids `setup_msg_decrypt_gcm` needing to hand back a pointer
        // into caller memory that only this one-shot path uses immediately.
        let params = match read_gcm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(self.op_err(e.rv())),
        };
        let iv = self.msg_iv.as_ref().unwrap().buf.clone();
        let tag = bytes_to_vec(params.pTag, tag_len);

        if plain.len() < cipher.len() {
            // The only non-fatal error: does not finalize the operation,
            // so the caller can retry with a correctly-sized buffer.
            return Err(Error::buf_too_small(cipher.len()));
        }

        let gcm = match AesGcm::new(&self.key, tag_len) {
            Ok(g) => g,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        // GCM tag-verification failure is an AEAD decrypt failure, not a
        // signature/MAC failure: PKCS#11 and this codebase reserve
        // CKR_SIGNATURE_INVALID for the latter (see the generic
        // `From<awslc::Error> for Error` mapping in `src/error.rs`, which
        // correctly maps `VerifyFailed` to `CKR_SIGNATURE_INVALID` for that
        // other context) and use CKR_ENCRYPTED_DATA_INVALID for every AEAD
        // tag failure elsewhere (e.g. `src/ossl/aes.rs`'s
        // `msg_decrypt_final`, `src/ossl/chacha20.rs`). Bypass the generic
        // conversion here and map explicitly instead of using `?`.
        let n = match gcm.open(&iv, adata, cipher, &tag, plain) {
            Ok(n) => n,
            Err(_) => return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID)),
        };

        // See msg_encrypt_gcm's doc comment for why FIPS approval for
        // AEAD is determined explicitly here rather than through the
        // generic clear()/update() bracket.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_DECRYPT,
            tag_len,
        )?;

        Ok(n)
    }

    /// CCM one-shot message decryption, mirroring
    /// `crate::ossl::aes::AesOperation::init_msg_params`'s `CKM_AES_CCM`
    /// arm on the decrypt side (nonce/data/tag-length validation; the
    /// nonce generator fields are ignored entirely on decrypt, matching
    /// the reference -- `init_msg_params` only reads `ulNonceFixedBits`/
    /// `nonceGenerator` `if self.op == CKF_MESSAGE_ENCRYPT`) plus
    /// `msg_decrypt_final`'s CCM branch (`ulDataLen == cipher.len()`
    /// check, same reasoning as `msg_encrypt_ccm`'s `plain.len()` check).
    /// The CCM analogue of [`Self::setup_msg_decrypt_gcm`]. Returns the tag
    /// length in bytes and the declared total data length (`ulDataLen`),
    /// for the same reason [`Self::setup_msg_encrypt_ccm`] does: the caller
    /// checks the actual ciphertext length against it at whichever point
    /// that length is actually known (immediately for one-shot, at `Final`
    /// for `Begin`/`Next`/`Final`).
    fn setup_msg_decrypt_ccm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
    ) -> Result<(usize, usize)> {
        // See setup_msg_encrypt_gcm's doc comment: none of this pure
        // parameter validation finalizes the operation on error.
        let params = match read_ccm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        if params.pNonce.is_null() || params.pMAC.is_null() {
            return Err(Error::ck_rv(CKR_ARGUMENTS_BAD));
        }
        let max_data_len = match ccm_max_data_len(params.ulNonceLen) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if params.ulDataLen > max_data_len
            || params.ulDataLen > (CK_ULONG::MAX - params.ulMACLen)
        {
            return Err(Error::ck_rv(CKR_MECHANISM_PARAM_INVALID));
        }
        match params.ulMACLen {
            4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
            _ => return Err(Error::ck_rv(CKR_ARGUMENTS_BAD)),
        }
        let tag_len = match usize::try_from(params.ulMACLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let nonce_len = match usize::try_from(params.ulNonceLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        let data_len = match usize::try_from(params.ulDataLen) {
            Ok(v) => v,
            Err(_) => return Err(Error::ck_rv(CKR_GENERAL_ERROR)),
        };
        // See setup_msg_encrypt_ccm's identical check.
        if data_len > MAX_CCM_BUF {
            return Err(Error::ck_rv(CKR_DATA_LEN_RANGE));
        }
        let nonce = bytes_to_vec(params.pNonce, nonce_len);

        // See msg_decrypt_gcm's doc comment: the nonce generator fields
        // are decrypt-side no-ops, so the nonce is always used verbatim.
        self.msg_iv = Some(AesIvData {
            buf: nonce,
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        });
        Ok((tag_len, data_len))
    }

    fn msg_decrypt_ccm(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        let (tag_len, data_len) =
            self.setup_msg_decrypt_ccm(param, paramlen)?;
        if cipher.len() != data_len {
            return Err(self.op_err(CKR_DATA_LEN_RANGE));
        }
        // Re-parse to read the MAC bytes: see msg_decrypt_gcm's identical
        // comment for why.
        let params = match read_ccm_message_params(param, paramlen) {
            Ok(p) => p,
            Err(e) => return Err(self.op_err(e.rv())),
        };
        let nonce = self.msg_iv.as_ref().unwrap().buf.clone();
        let tag = bytes_to_vec(params.pMAC, tag_len);

        if plain.len() < cipher.len() {
            // The only non-fatal error: does not finalize the operation,
            // so the caller can retry with a correctly-sized buffer.
            return Err(Error::buf_too_small(cipher.len()));
        }

        let ccm = match AesCcm::new(&self.key, tag_len) {
            Ok(c) => c,
            Err(e) => return Err(self.op_err(Error::from(e).rv())),
        };
        // Same CKR_ENCRYPTED_DATA_INVALID-not-CKR_SIGNATURE_INVALID
        // reasoning as msg_decrypt_gcm.
        let n = match ccm.open(&nonce, adata, cipher, &tag, plain) {
            Ok(n) => n,
            Err(_) => return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID)),
        };

        // See msg_encrypt_gcm's doc comment for why FIPS approval for
        // AEAD is determined explicitly here rather than through the
        // generic clear()/update() bracket.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_DECRYPT,
            tag_len,
        )?;

        Ok(n)
    }
}

impl MsgEncryption for AesOperation {
    /// Dispatches to [`AesOperation::msg_encrypt_gcm`] or
    /// [`AesOperation::msg_encrypt_ccm`] -- the only two mechanisms
    /// message mode supports (see `msg_encrypt_init`'s doc comment).
    fn msg_encrypt(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_AES_GCM => {
                self.msg_encrypt_gcm(param, paramlen, adata, plain, cipher)
            }
            CKM_AES_CCM => {
                self.msg_encrypt_ccm(param, paramlen, adata, plain, cipher)
            }
            _ => Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }

    /// Begins a `Begin`/`Next`/`Final` message: runs the same param
    /// parsing/IV-generation/validation as the one-shot `msg_encrypt_gcm`/
    /// `msg_encrypt_ccm` (via their shared `setup_msg_encrypt_gcm`/
    /// `setup_msg_encrypt_ccm` helpers), stores the AAD and resets the
    /// plaintext buffer, and marks the operation busy. No real encryption
    /// happens here -- see `msg_encrypt_final`'s doc comment for why this
    /// backend buffers the whole message rather than truly streaming it.
    fn msg_encrypt_begin(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }
        self.msg_ccm_data_len = match self.mech {
            CKM_AES_GCM => {
                let (tag_len, _tag_ptr) =
                    self.setup_msg_encrypt_gcm(param, paramlen)?;
                self.msg_tag_len = Some(tag_len);
                None
            }
            CKM_AES_CCM => {
                let (tag_len, _mac_ptr, data_len) =
                    self.setup_msg_encrypt_ccm(param, paramlen)?;
                self.msg_tag_len = Some(tag_len);
                Some(data_len)
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };
        self.msg_aad = aad.to_vec();
        self.msg_buffer.clear();
        self.in_use = true;
        Ok(())
    }

    /// Buffers `plain` for the eventual real encryption at `msg_encrypt_
    /// final`; never emits any ciphertext itself (see that method's doc
    /// comment).
    fn msg_encrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(data_len) = self.msg_ccm_data_len {
            if self.msg_buffer.len() + plain.len() > data_len {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
        } else if self.msg_buffer.len() + plain.len() > MAX_CCM_BUF {
            // GCM has no declared total length to check against (unlike
            // CCM's msg_ccm_data_len, itself now capped at MAX_CCM_BUF in
            // setup_msg_encrypt_ccm), so the cap has to be enforced directly
            // on the accumulated buffer here -- otherwise a caller could
            // grow msg_buffer without bound across repeated Next calls that
            // never reach Final.
            return Err(self.op_err(CKR_DATA_LEN_RANGE));
        }
        self.msg_buffer.extend_from_slice(plain);
        Ok(0)
    }

    /// Appends `plain`'s final chunk to the buffer `msg_encrypt_begin`/
    /// `msg_encrypt_next` filled, then performs the real one-shot seal over
    /// everything accumulated, using the IV/AAD/tag length `msg_encrypt_
    /// begin` already established. AWS-LC's `AesGcm`/`AesCcm` are one-shot
    /// primitives with no incremental update (unlike the reference
    /// backend's OpenSSL `EVP_CIPHER`-based GCM, which streams for real --
    /// see the design discussion this implementation follows), so this
    /// backend trades true incremental output for buffering the whole
    /// message in memory until `Final`; both are PKCS#11-legal (`Next` may
    /// return 0 bytes) and the reference's own CCM side already buffers
    /// the same way for the same underlying reason (CCM needs the total
    /// length up front regardless of backend).
    fn msg_encrypt_final(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(data_len) = self.msg_ccm_data_len {
            if self.msg_buffer.len() + plain.len() != data_len {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
        }
        let total_len = self.msg_buffer.len() + plain.len();
        if cipher.len() < total_len {
            // The only non-fatal error: does not touch msg_buffer or
            // in_use, so the caller can retry with a correctly-sized
            // buffer without plain being buffered twice.
            return Err(Error::buf_too_small(total_len));
        }
        self.msg_buffer.extend_from_slice(plain);

        let tag_len = self.msg_tag_len.unwrap();
        let iv = self.msg_iv.as_ref().unwrap().buf.clone();
        let mut sealed = vec![0u8; total_len + tag_len];
        let result =
            new_one_shot_aead(self.mech, &self.key, tag_len).and_then(|aead| {
                aead.seal(&iv, &self.msg_aad, &self.msg_buffer, &mut sealed)
                    .map_err(Error::from)
            });
        zeromem(&mut self.msg_buffer);
        let n = match result {
            Ok(n) => n,
            Err(e) => return Err(self.op_err(e.rv())),
        };
        cipher[..total_len].copy_from_slice(&sealed[..total_len]);
        let tag_ptr = match self.mech {
            CKM_AES_GCM => match read_gcm_message_params(param, paramlen) {
                Ok(p) => p.pTag,
                Err(e) => return Err(self.op_err(e.rv())),
            },
            CKM_AES_CCM => match read_ccm_message_params(param, paramlen) {
                Ok(p) => p.pMAC,
                Err(e) => return Err(self.op_err(e.rv())),
            },
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };
        // SAFETY: tag_ptr is this call's own CK_GCM_MESSAGE_PARAMS::pTag/
        // CK_CCM_MESSAGE_PARAMS::pMAC, freshly re-parsed above and not
        // independently null-checked at this point; write_out is a no-op
        // if it's null, and otherwise it points at a caller-owned buffer
        // sized for the tag length this same params struct declared.
        unsafe {
            crate::lowlevel::cipher::write_out(tag_ptr, &sealed[total_len..n]);
        }

        // See msg_encrypt_gcm's doc comment for why FIPS approval for AEAD
        // is determined explicitly here rather than through the generic
        // clear()/update() bracket.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_ENCRYPT,
            tag_len,
        )?;

        self.in_use = false;
        Ok(total_len)
    }

    /// `self.in_use` is false only when no `Begin` has run yet, which means
    /// this query precedes a one-shot `msg_encrypt` call instead of a real
    /// `Next`/`Final` -- both `fn_encrypt_message`'s query (`fin: true`)
    /// and `src/encryption.rs`'s `aes_gcm_encrypt` (`fin: false`, called
    /// directly on a fresh `msg_encrypt_init`'d operation, bypassing
    /// `C_EncryptMessageBegin` entirely) rely on getting the *whole*
    /// `data_len` back regardless of `fin` in that case, since the single
    /// upcoming `msg_encrypt` call produces the entire ciphertext at once.
    /// Once a real `Begin` has run (`self.in_use` true), `Next` never
    /// emits output (everything is buffered) and `Final` emits everything
    /// buffered so far plus this call's own `data_len` -- the same
    /// convention `key_wrap_encrypt`'s `encryption_len` uses for the
    /// identical buffer-then-finalize reason.
    fn msg_encryption_len(
        &mut self,
        data_len: usize,
        fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Ok(data_len);
        }
        if !fin {
            return Ok(0);
        }
        Ok(self.msg_buffer.len() + data_len)
    }
}

impl MsgDecryption for AesOperation {
    /// Dispatches to [`AesOperation::msg_decrypt_gcm`] or
    /// [`AesOperation::msg_decrypt_ccm`] -- the only two mechanisms
    /// message mode supports (see `msg_encrypt_init`'s doc comment).
    fn msg_decrypt(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        adata: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_AES_GCM => {
                self.msg_decrypt_gcm(param, paramlen, adata, cipher, plain)
            }
            CKM_AES_CCM => {
                self.msg_decrypt_ccm(param, paramlen, adata, cipher, plain)
            }
            _ => Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }

    /// The decrypt-side counterpart of `msg_encrypt_begin`: establishes the
    /// (always caller-supplied, never generated) IV via `setup_msg_decrypt_
    /// gcm`/`setup_msg_decrypt_ccm`, stores the AAD, resets the ciphertext
    /// buffer, and marks the operation busy.
    fn msg_decrypt_begin(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }
        self.msg_ccm_data_len = match self.mech {
            CKM_AES_GCM => {
                let tag_len = self.setup_msg_decrypt_gcm(param, paramlen)?;
                self.msg_tag_len = Some(tag_len);
                None
            }
            CKM_AES_CCM => {
                let (tag_len, data_len) =
                    self.setup_msg_decrypt_ccm(param, paramlen)?;
                self.msg_tag_len = Some(tag_len);
                Some(data_len)
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };
        self.msg_aad = aad.to_vec();
        self.msg_buffer.clear();
        self.in_use = true;
        Ok(())
    }

    /// Buffers `cipher` for the eventual real decryption at `msg_decrypt_
    /// final`; never emits any plaintext itself (see `msg_encrypt_final`'s
    /// doc comment for why this backend buffers instead of streaming).
    fn msg_decrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(data_len) = self.msg_ccm_data_len {
            if self.msg_buffer.len() + cipher.len() > data_len {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
        } else if self.msg_buffer.len() + cipher.len() > MAX_CCM_BUF {
            // See msg_encrypt_next's identical GCM-side check.
            return Err(self.op_err(CKR_DATA_LEN_RANGE));
        }
        self.msg_buffer.extend_from_slice(cipher);
        Ok(0)
    }

    /// Appends `cipher`'s final chunk to the buffer `msg_decrypt_begin`/
    /// `msg_decrypt_next` filled, then performs the real one-shot open
    /// (tag verification included) over everything accumulated, using the
    /// IV/AAD/tag length `msg_decrypt_begin` already established. See
    /// `msg_encrypt_final`'s doc comment for the buffering rationale.
    fn msg_decrypt_final(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(data_len) = self.msg_ccm_data_len {
            if self.msg_buffer.len() + cipher.len() != data_len {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
        }
        let total_len = self.msg_buffer.len() + cipher.len();
        if plain.len() < total_len {
            // The only non-fatal error: does not touch msg_buffer or
            // in_use, so the caller can retry with a correctly-sized
            // buffer without cipher being buffered twice.
            return Err(Error::buf_too_small(total_len));
        }
        self.msg_buffer.extend_from_slice(cipher);

        let tag_len = self.msg_tag_len.unwrap();
        let tag_ptr_result = match self.mech {
            CKM_AES_GCM => {
                read_gcm_message_params(param, paramlen).map(|p| p.pTag)
            }
            CKM_AES_CCM => {
                read_ccm_message_params(param, paramlen).map(|p| p.pMAC)
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };
        let tag_ptr = match tag_ptr_result {
            Ok(p) => p,
            Err(e) => return Err(self.op_err(e.rv())),
        };
        let tag = bytes_to_vec(tag_ptr, tag_len);
        let iv = self.msg_iv.as_ref().unwrap().buf.clone();

        // An invalid `self.mech` is defensive/unreachable (`msg_decrypt_
        // begin` already restricts it to GCM/CCM before this point) and
        // keeps its own distinct CKR_GENERAL_ERROR; construction or
        // open() failing for any other reason collapses to
        // CKR_ENCRYPTED_DATA_INVALID-not-CKR_SIGNATURE_INVALID (same
        // reasoning as msg_decrypt_gcm/msg_decrypt_ccm) -- matches this
        // function's pre-existing error-mapping exactly, just built on
        // `new_one_shot_aead` instead of a duplicated per-mechanism match.
        if !matches!(self.mech, CKM_AES_GCM | CKM_AES_CCM) {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        let result = new_one_shot_aead(self.mech, &self.key, tag_len)
            .map_err(|_| ())
            .and_then(|aead| {
                aead.open(&iv, &self.msg_aad, &self.msg_buffer, &tag, plain)
                    .map_err(|_| ())
            });
        zeromem(&mut self.msg_buffer);
        let n = match result {
            Ok(n) => n,
            Err(()) => return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID)),
        };

        // See msg_encrypt_gcm's doc comment for why FIPS approval for AEAD
        // is determined explicitly here rather than through the generic
        // clear()/update() bracket.
        #[cfg(feature = "fips")]
        fips_approval_aead(
            &mut self.fips_approval,
            self.msg_iv.as_ref().unwrap(),
            CKF_MESSAGE_DECRYPT,
            tag_len,
        )?;

        self.in_use = false;
        Ok(n)
    }

    /// See `msg_encryption_len`'s doc comment for the `self.in_use`
    /// distinction (mirrors `src/encryption.rs`'s `aes_gcm_decrypt`, the
    /// decrypt-side counterpart of `aes_gcm_encrypt`).
    fn msg_decryption_len(
        &mut self,
        data_len: usize,
        fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Ok(data_len);
        }
        if !fin {
            return Ok(0);
        }
        Ok(self.msg_buffer.len() + data_len)
    }
}

impl Encryption for AesOperation {
    /// One-shot encryption: `encrypt_update` followed by `encrypt_final`,
    /// mirroring `crate::ossl::aes::AesOperation::encrypt`. For `key_wrap`
    /// operations this composition still works unmodified: `encrypt_update`
    /// just buffers (AES-KW has no real incremental output), and
    /// `encrypt_final` does the whole wrap over everything buffered so
    /// far, exactly the multi-part streaming case the reference also
    /// supports for these mechanisms -- the same buffer-then-wrap-at-final
    /// path serves both.
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let outl = self.encrypt_update(plain, cipher)?;
        if outl > cipher.len() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        Ok(outl + self.encrypt_final(&mut cipher[outl..])?)
    }

    fn encrypt_update(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        debug_assert!(
            self.encrypting,
            "encrypt_update on a decrypt-mode AesOperation"
        );
        self.in_use = true;
        let outlen = self.encryption_len(plain.len(), false)?;
        if cipher.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(Error::buf_too_small(outlen));
        }
        if let Some(state) = self.key_wrap.as_mut() {
            state.buffer.extend_from_slice(plain);
            return Ok(0);
        }
        if self.classic.is_none() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        let result = {
            let classic = self.classic.as_mut().unwrap();
            Self::classic_encrypt_update(
                classic,
                &self.key,
                plain,
                cipher,
                #[cfg(feature = "fips")]
                &mut self.fips_approval,
            )
        };
        match result {
            Ok(n) => Ok(n),
            Err(rv) => Err(self.op_err(rv)),
        }
    }

    fn encrypt_final(&mut self, cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.key_wrap.is_some() {
            return self.key_wrap_finalize_encrypt(cipher);
        }
        // Buffer-too-small pre-check: must happen before finalizing, and
        // mirrors the exact required sizes `crate::ossl::aes` checks for
        // these same mechanisms (see classic_encrypt_final's doc comment
        // for why the AEAD case differs in *value*, not in convention).
        let required = match &self.classic {
            Some(ClassicMode::Block { padded: true, .. }) => {
                Some(AES_BLOCK_SIZE)
            }
            Some(ClassicMode::Ccm { taglen, .. }) => Some(*taglen),
            Some(ClassicMode::Gcm { taglen, buffer, .. }) => {
                Some(buffer.len() + *taglen)
            }
            _ => None,
        };
        if let Some(need) = required {
            if cipher.len() < need {
                return Err(Error::buf_too_small(need));
            }
        }
        if self.classic.is_none() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }

        let result = {
            let classic = self.classic.as_mut().unwrap();
            Self::classic_encrypt_final(
                classic,
                &self.key,
                cipher,
                #[cfg(feature = "fips")]
                &mut self.fips_approval,
            )
        };
        self.finalized = true;
        result.map_err(Error::ck_rv)
    }

    /// Mirrors `crate::ossl::aes::AesOperation::encryption_len` for every
    /// mode this backend implements, except CKM_AES_GCM: since
    /// `awslc::cipher::AesGcm` is a one-shot AEAD with no incremental
    /// update, `encrypt_update` never emits output early (everything is
    /// buffered and emitted at once by `encrypt_final`), so `fin: false`
    /// always predicts 0 and `fin: true` predicts the *entire* remaining
    /// buffered message, not just `data_len + taglen` -- see the
    /// module-level doc comment.
    fn encryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(state) = &self.key_wrap {
            // key_wrap operations only ever emit output from
            // encrypt_final, once everything is buffered: an `encrypt_
            // update` query (`fin: false`) always predicts 0, and a
            // `encrypt_final` query (`fin: true`) predicts the wrap of
            // everything buffered so far plus this call's own `data_len`
            // (matching `encrypt_update`'s own pre-check, which queries
            // with `fin: false` before buffering `plain`). Uses the same
            // query mode (`output.len() == 0`) `wrap`'s own callers use,
            // so no real `AesKeyWrap` call happens here.
            if !fin {
                return Ok(0);
            }
            let total_len = state.buffer.len() + data_len;
            let outcome = match state.variant {
                KeyWrapVariant::Plain => Self::wrap_plain(
                    &state.kw,
                    &vec![0u8; total_len],
                    None,
                    &mut [],
                ),
                KeyWrapVariant::Pkcs7 => Self::wrap_pkcs7(
                    &state.kw,
                    &mut vec![0u8; total_len],
                    None,
                    &mut [],
                ),
                KeyWrapVariant::Kwp => Self::wrap_kwp(
                    &state.kw,
                    &vec![0u8; total_len],
                    None,
                    &mut [],
                ),
            };
            // Matches the classic-mode arm below: any error from a length
            // query (this is never a buffer-size query itself -- `output`
            // is always empty here -- so `Error::buf_too_small` is not a
            // possible outcome) finalizes the operation, same as a real
            // encrypt failure would.
            return match outcome {
                Ok(n) => Ok(n),
                Err(e) => Err(self.op_err(e.rv())),
            };
        }
        let classic = match &self.classic {
            Some(c) => c,
            None => return Err(CKR_GENERAL_ERROR)?,
        };
        let outcome: std::result::Result<usize, CK_RV> = match classic {
            ClassicMode::Block {
                padded,
                block_aligned,
                buffer,
                ..
            } => {
                let buflen = buffer.len();
                if fin {
                    if *padded {
                        Ok(((buflen + data_len + AES_BLOCK_SIZE)
                            / AES_BLOCK_SIZE)
                            * AES_BLOCK_SIZE)
                    } else if *block_aligned {
                        if (buflen + data_len) % AES_BLOCK_SIZE != 0 {
                            Err(CKR_DATA_LEN_RANGE)
                        } else {
                            Ok(buflen + data_len)
                        }
                    } else {
                        Ok(data_len)
                    }
                } else if *block_aligned {
                    Ok(((buflen + data_len) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE)
                } else {
                    Ok(data_len)
                }
            }
            ClassicMode::Ccm {
                taglen,
                datalen,
                buffer,
                done,
                ..
            } => {
                let buflen = buffer.len();
                if *done {
                    // `seal` already ran (during whichever update call
                    // completed `datalen`); only the tag is left.
                    if fin {
                        Ok(*taglen)
                    } else {
                        Ok(0)
                    }
                } else if fin {
                    if buflen + data_len != *datalen {
                        Err(CKR_DATA_LEN_RANGE)
                    } else {
                        Ok(*datalen + *taglen)
                    }
                } else {
                    Ok(*datalen + *taglen)
                }
            }
            ClassicMode::Gcm { taglen, buffer, .. } => {
                let buflen = buffer.len();
                if fin {
                    Ok(buflen + data_len + *taglen)
                } else {
                    Ok(0)
                }
            }
        };
        match outcome {
            Ok(n) => Ok(n),
            Err(rv) => Err(self.op_err(rv)),
        }
    }
}

impl Decryption for AesOperation {
    /// One-shot decryption: `decrypt_update` followed by `decrypt_final`,
    /// mirroring `crate::ossl::aes::AesOperation::decrypt`. See
    /// `Encryption::encrypt`'s doc comment for why this composition also
    /// serves `key_wrap` operations unmodified.
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let outl = self.decrypt_update(cipher, plain)?;
        if outl > plain.len() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        Ok(outl + self.decrypt_final(&mut plain[outl..])?)
    }

    fn decrypt_update(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        debug_assert!(
            !self.encrypting,
            "decrypt_update on an encrypt-mode AesOperation"
        );
        self.in_use = true;
        let outlen = self.decryption_len(cipher.len(), false)?;
        if plain.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(Error::buf_too_small(outlen));
        }
        if let Some(state) = self.key_wrap.as_mut() {
            state.buffer.extend_from_slice(cipher);
            return Ok(0);
        }
        if self.classic.is_none() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        let result = {
            let classic = self.classic.as_mut().unwrap();
            Self::classic_decrypt_update(
                classic,
                &self.key,
                cipher,
                plain,
                #[cfg(feature = "fips")]
                &mut self.fips_approval,
            )
        };
        match result {
            Ok(n) => Ok(n),
            Err(rv) => Err(self.op_err(rv)),
        }
    }

    fn decrypt_final(&mut self, plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.key_wrap.is_some() {
            return self.key_wrap_finalize_decrypt(plain);
        }
        // Buffer-too-small pre-check, symmetric with `encrypt_final`'s
        // (see that method's comment): without this, an undersized
        // `plain` buffer falls through to whichever error
        // `classic_decrypt_final`'s underlying `BlockCipher`/`AesGcm`
        // call happens to return (e.g. CKR_DEVICE_ERROR, which -- unlike
        // CKR_BUFFER_TOO_SMALL -- isn't recoverable: the operation is
        // finalized and the caller can't just retry with a bigger
        // buffer).
        let required = match &self.classic {
            Some(ClassicMode::Block { padded: true, .. }) => {
                Some(AES_BLOCK_SIZE)
            }
            Some(ClassicMode::Gcm { taglen, buffer, .. }) => {
                Some(buffer.len().saturating_sub(*taglen))
            }
            _ => None,
        };
        if let Some(need) = required {
            if plain.len() < need {
                return Err(Error::buf_too_small(need));
            }
        }
        if self.classic.is_none() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        let result = {
            let classic = self.classic.as_mut().unwrap();
            Self::classic_decrypt_final(
                classic,
                &self.key,
                plain,
                #[cfg(feature = "fips")]
                &mut self.fips_approval,
            )
        };
        self.finalized = true;
        result.map_err(Error::ck_rv)
    }

    /// Mirrors `crate::ossl::aes::AesOperation::decryption_len`; see
    /// `encryption_len`'s doc comment for why CKM_AES_GCM's formula
    /// differs from the reference's.
    fn decryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if let Some(state) = &self.key_wrap {
            // Only decrypt_final ever emits output (see encryption_len's
            // key_wrap comment for the symmetric encrypt-side rationale);
            // a decrypt_update query (`fin: false`) always predicts 0.
            if !fin {
                return Ok(0);
            }
            // A safe upper bound over everything buffered so far plus this
            // call's own data_len, same convention `ClassicMode::Block`'s
            // own padded arm above uses: PKCS7/KWP may return less once
            // really unwrapped (their real length isn't knowable without
            // doing that), but plain RFC 3394 unwrap's length is always
            // exactly this for all three variants -- the 8-byte integrity/
            // IV overhead is the only thing ever subtracted.
            return match (state.buffer.len() + data_len).checked_sub(8) {
                Some(n) => Ok(n),
                None => Err(self.op_err(CKR_ENCRYPTED_DATA_LEN_RANGE)),
            };
        }
        let classic = match &self.classic {
            Some(c) => c,
            None => return Err(CKR_GENERAL_ERROR)?,
        };
        let outcome: std::result::Result<usize, CK_RV> = match classic {
            ClassicMode::Block {
                padded,
                block_aligned,
                buffer,
                ..
            } => {
                let buflen = buffer.len();
                if fin {
                    if *padded || *block_aligned {
                        if (buflen + data_len) % AES_BLOCK_SIZE != 0 {
                            Err(CKR_ENCRYPTED_DATA_LEN_RANGE)
                        } else {
                            Ok(buflen + data_len)
                        }
                    } else {
                        Ok(data_len)
                    }
                } else if *padded {
                    let total = buflen + data_len;
                    Ok(if total == 0 {
                        0
                    } else {
                        ((total - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
                    })
                } else if *block_aligned {
                    Ok(((buflen + data_len) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE)
                } else {
                    Ok(data_len)
                }
            }
            ClassicMode::Ccm {
                taglen,
                datalen,
                buffer,
                done,
                ..
            } => {
                let buflen = buffer.len();
                if *done {
                    // `open` already ran and produced all the plaintext;
                    // nothing more is left for decrypt_final.
                    Ok(0)
                } else if fin {
                    if buflen + data_len != *datalen + *taglen {
                        Err(CKR_ENCRYPTED_DATA_LEN_RANGE)
                    } else {
                        Ok(*datalen)
                    }
                } else {
                    Ok(*datalen)
                }
            }
            ClassicMode::Gcm { taglen, buffer, .. } => {
                let buflen = buffer.len();
                if fin {
                    if buflen + data_len < *taglen {
                        Err(CKR_ENCRYPTED_DATA_LEN_RANGE)
                    } else {
                        Ok(buflen + data_len - *taglen)
                    }
                } else {
                    Ok(0)
                }
            }
        };
        match outcome {
            Ok(n) => Ok(n),
            Err(rv) => Err(self.op_err(rv)),
        }
    }
}

/// The AES MAC operation (`CKM_AES_MAC`/`CKM_AES_MAC_GENERAL`): CBC-MAC.
/// This is explicitly NOT a separate cryptographic primitive -- it's a
/// specific usage pattern of CBC encryption, computed by feeding
/// block-sized chunks through an internal CBC `AesOperation` (constructed
/// via `AesOperation::encrypt_new` with `CKM_AES_CBC` and an all-zero IV,
/// exactly as the reference does) and keeping only the last output block
/// as the running MAC value, mirroring
/// `crate::ossl::aes::AesMacOperation`'s own composition.
#[derive(Debug)]
pub struct AesMacOperation {
    /// The specific MAC mechanism being used.
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// Buffer to hold one full block of data, will be zero-padded for the
    /// last (possibly partial) block.
    padbuf: [u8; AES_BLOCK_SIZE],
    /// Size of the data stored in `padbuf` at any given time.
    padlen: usize,
    /// Holds the last CBC output block: the running/final MAC value.
    macbuf: [u8; AES_BLOCK_SIZE],
    /// Size of the requested MAC output.
    maclen: usize,
    /// Internal CBC encryption operation this type's CBC-MAC is built on.
    op: AesOperation,
    /// FIPS approval status for the operation. Derived entirely from the
    /// internal `op`'s own status (see `finalize`) -- this type never
    /// calls into AWS-LC directly, so it has no service-indicator calls
    /// of its own to bracket.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization.
    signature: Option<Vec<u8>>,
}

impl Drop for AesMacOperation {
    fn drop(&mut self) {
        zeromem(&mut self.padbuf);
        zeromem(&mut self.macbuf);
    }
}

impl AesMacOperation {
    /// Registers the plain-MAC mechanisms, mirroring
    /// `crate::ossl::aes::AesMacOperation::register_mechanisms` (same
    /// `CKF_SIGN | CKF_VERIFY` mechanism-info entry,
    /// `crate::aes::AES_MECHS[4]`, that `AesCmacOperation` below also
    /// uses).
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_MAC, CKM_AES_MAC_GENERAL] {
            mechs.add_mechanism(*ckm, &crate::aes::AES_MECHS[4]);
        }
    }

    /// Initializes and returns a MAC (CBC-MAC) operation.
    pub fn init(
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<&[u8]>,
    ) -> Result<AesMacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_MAC_GENERAL => {
                let params = mech.get_parameters::<CK_MAC_GENERAL_PARAMS>()?;
                let val = params as usize;
                if val > AES_BLOCK_SIZE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                val
            }
            CKM_AES_MAC => {
                if mech.ulParameterLen != 0 {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                AES_BLOCK_SIZE / 2
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        // The internal CBC operation always uses an all-zero IV: CBC-MAC's
        // chaining starts from zero, mirroring the reference's own
        // `AesIvData::simple`-style zero IV for this exact purpose.
        let iv = [0u8; AES_BLOCK_SIZE];
        let cbc_mech = CK_MECHANISM {
            mechanism: CKM_AES_CBC,
            pParameter: iv.as_ptr() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };
        Ok(AesMacOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            padbuf: [0; AES_BLOCK_SIZE],
            padlen: 0,
            macbuf: [0; AES_BLOCK_SIZE],
            maclen: maclen,
            op: AesOperation::encrypt_new(&cbc_mech, key)?,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
            signature: match signature {
                Some(s) => {
                    if s.len() != maclen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
        })
    }

    /// Begins a MAC computation.
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Feeds in the next data buffer into the MAC computation, buffering
    /// up to whole blocks and running each completed block through the
    /// internal CBC operation, keeping only its output as the running MAC
    /// value (`self.macbuf`).
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        let mut data_len = self.padlen + data.len();
        let mut cursor = 0;

        if data_len < AES_BLOCK_SIZE {
            self.padbuf[self.padlen..data_len].copy_from_slice(data);
            self.padlen = data_len;
            return Ok(());
        }
        if self.padlen > 0 {
            /* first full block */
            cursor = AES_BLOCK_SIZE - self.padlen;
            self.padbuf[self.padlen..].copy_from_slice(&data[..cursor]);
            let outlen =
                self.op.encrypt_update(&self.padbuf, &mut self.macbuf)?;
            if outlen != AES_BLOCK_SIZE {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            data_len -= AES_BLOCK_SIZE;
        }

        /* whole blocks */
        while data_len > AES_BLOCK_SIZE {
            let outlen = self.op.encrypt_update(
                &data[cursor..(cursor + AES_BLOCK_SIZE)],
                &mut self.macbuf,
            )?;
            if outlen != AES_BLOCK_SIZE {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            cursor += AES_BLOCK_SIZE;
            data_len -= AES_BLOCK_SIZE;
        }

        if data_len > 0 {
            self.padbuf[..data_len].copy_from_slice(&data[cursor..]);
        }
        self.padlen = data_len;
        Ok(())
    }

    /// Finalizes the MAC computation and returns the (possibly truncated)
    /// output in the provided buffer.
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        if output.len() != self.maclen {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if self.padlen > 0 {
            /* last full block, zero-padded */
            self.padbuf[self.padlen..].fill(0);
            let outlen =
                self.op.encrypt_update(&self.padbuf, &mut self.macbuf)?;
            if outlen != AES_BLOCK_SIZE {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }

        output.copy_from_slice(&self.macbuf[..output.len()]);

        #[cfg(feature = "fips")]
        {
            if self.op.fips_approved().is_some_and(|b| b == false) {
                self.fips_approval.set(false);
            }
            self.fips_approval.finalize();
        }
        Ok(())
    }

    /// Finalizes the MAC computation and checks the signature.
    fn finalize_ver(&mut self, signature: Option<&[u8]>) -> Result<()> {
        let mut computed = vec![0u8; self.maclen];
        self.finalize(computed.as_mut_slice())?;

        let sig = match signature {
            Some(sig) => sig,
            None => match &self.signature {
                Some(sig) => sig.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        if !constant_time_eq(&computed, sig) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }
}

impl MechOperation for AesMacOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
}

/// Implements the Sign interface for the AES MAC operation.
///
/// All methods just call the related internal method.
impl Sign for AesMacOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the Verify interface for the AES MAC operation.
///
/// All methods just call the related internal method.
impl Verify for AesMacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        Verify::verify_final(self, signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.finalize_ver(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the VerifySignature interface for the AES MAC operation.
///
/// All methods call the internal methods for computation, and then
/// compare the result with the signature stashed by the init function.
impl VerifySignature for AesMacOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        VerifySignature::verify_final(self)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        self.finalize_ver(None)
    }
}

/// The AES CMAC operation (`CKM_AES_CMAC`/`CKM_AES_CMAC_GENERAL`), built
/// directly on `awslc::mac::Cmac` (RFC 4493 AES-CMAC, already verified
/// against the RFC 4493 known-answer vector at that layer),
/// mirroring `crate::ossl::aes::AesCmacOperation`'s composition over its
/// own `OsslMac` CMAC context.
#[derive(Debug)]
pub struct AesCmacOperation {
    /// The specific CMAC mechanism being used.
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The underlying AWS-LC CMAC context.
    ctx: Cmac,
    /// The MAC length.
    maclen: usize,
    /// FIPS approval status for the operation. Only `finalize`'s
    /// `CMAC_Final` call is bracketed: AWS-LC's `CMAC_Init`/`CMAC_Update`
    /// both wrap their work in
    /// `FIPS_service_indicator_lock_state`/`unlock_state` (see
    /// `crypto/fipsmodule/cmac/cmac.c`), which suppresses any
    /// service-indicator movement from the underlying AES-CBC calls they
    /// make; only `CMAC_Final` calls `AES_CMAC_verify_service_indicator`
    /// (after unlocking), which is the sole point where the indicator can
    /// move (and only for 128/256-bit keys, never 192-bit). Bracketing
    /// `update`/`begin` here would observe no movement and permanently
    /// latch approval to `false`, verified empirically before writing
    /// this.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization.
    signature: Option<Vec<u8>>,
}

impl AesCmacOperation {
    /// Registers the CMAC mechanisms, mirroring
    /// `crate::ossl::aes::AesCmacOperation::register_mechanisms`.
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_CMAC, CKM_AES_CMAC_GENERAL] {
            mechs.add_mechanism(*ckm, &crate::aes::AES_MECHS[4]);
        }
    }

    /// Initializes and returns a CMAC operation.
    pub fn init(
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<&[u8]>,
    ) -> Result<AesCmacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_CMAC_GENERAL => {
                let params = mech.get_parameters::<CK_MAC_GENERAL_PARAMS>()?;
                let val = params as usize;
                if val > AES_BLOCK_SIZE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                val
            }
            CKM_AES_CMAC => {
                if mech.ulParameterLen != 0 {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                AES_BLOCK_SIZE
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };

        // `key_data` holds the raw AES key from here on: every return
        // between acquiring it and handing it off to `Cmac::new` (which
        // copies what it needs into AWS-LC's own key schedule and does
        // not retain a reference to this buffer) must scrub it first,
        // matching this module's established convention for sensitive key
        // material (see `AesOperation::classic_new`'s doc comment).
        let mut key_data = key_bytes(key)?;
        match key_data.len() {
            16 | 24 | 32 => (),
            _ => {
                zeromem(&mut key_data);
                return Err(CKR_KEY_INDIGESTIBLE)?;
            }
        }

        let ctx = match Cmac::new(&key_data) {
            Ok(c) => c,
            Err(e) => {
                zeromem(&mut key_data);
                return Err(e)?;
            }
        };
        zeromem(&mut key_data);

        Ok(AesCmacOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            ctx: ctx,
            maclen: maclen,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
            signature: match signature {
                Some(s) => {
                    if s.len() != maclen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
        })
    }

    /// Begins a CMAC computation.
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Feeds in the next data buffer into the CMAC computation.
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        Ok(self.ctx.update(data)?)
    }

    /// Finalizes the CMAC computation and returns the (possibly
    /// truncated) output in the provided buffer.
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        /* It is valid to finalize without any update */
        self.in_use = true;
        self.finalized = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut buf = [0u8; AES_BLOCK_SIZE];
        let outlen = self.ctx.finalize(&mut buf)?;
        if outlen != AES_BLOCK_SIZE {
            zeromem(&mut buf);
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        output.copy_from_slice(&buf[..output.len()]);
        zeromem(&mut buf);

        #[cfg(feature = "fips")]
        {
            // NIST SP 800-38B A.2: for most applications, a Tlen of at
            // least 64 bits (8 bytes) should provide sufficient
            // protection against guessing attacks, matching
            // `crate::ossl::aes::AesCmacOperation::fips_approval_cmac`.
            if self.maclen < 8 {
                self.fips_approval.set(false);
            }
            self.fips_approval.finalize();
        }

        Ok(())
    }

    /// Finalizes the CMAC computation and checks the signature.
    fn finalize_ver(&mut self, signature: Option<&[u8]>) -> Result<()> {
        let mut computed = vec![0u8; self.maclen];
        self.finalize(computed.as_mut_slice())?;

        let sig = match signature {
            Some(sig) => sig,
            None => match &self.signature {
                Some(sig) => sig.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        if !constant_time_eq(&computed, sig) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }
}

impl MechOperation for AesCmacOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
}

/// Implements the (internal) Mac interface for the AES CMAC operation.
///
/// All methods just call the related internal method.
impl Mac for AesCmacOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> Result<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the Sign interface for the AES CMAC operation.
///
/// All methods just call the related internal method.
impl Sign for AesCmacOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the Verify interface for the AES CMAC operation.
///
/// All methods just call the related internal method.
impl Verify for AesCmacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        Verify::verify_final(self, signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.finalize_ver(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the VerifySignature interface for the AES CMAC operation.
///
/// All methods call the internal methods for computation, and then
/// compare the result with the signature stashed by the init function.
impl VerifySignature for AesCmacOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        VerifySignature::verify_final(self)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        self.finalize_ver(None)
    }
}

// Deliberately inline (unlike the reference backend's convention of
// keeping tests under src/tests/*.rs): most tests below exercise
// `AesOperation`'s private fields/methods directly (e.g. its internal
// classic-vs-message-mode state machine, IV-generation bookkeeping),
// which src/tests/*.rs cannot reach without either making that surface
// `pub(crate)` or duplicating it through the public `Mechanism` trait
// dispatch alone. Higher-level, trait-dispatch-only coverage for this
// module still lives in src/tests/aes.rs alongside the reference
// backend's own equivalent tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::Attribute;

    /// Builds a bare AES secret key `Object` carrying just `CKA_VALUE`,
    /// enough for `key_bytes`/`msg_encrypt_init`/`msg_decrypt_init` (which
    /// only ever read `CKA_VALUE`) -- mirroring how `src/encryption.rs`'s
    /// `ephemeral_key` produces a 32-byte AES-256 key, but without needing
    /// the full `AesKeyFactory`/`Mechanisms` machinery this module doesn't
    /// otherwise touch.
    fn test_key(value: &[u8]) -> Object {
        let mut obj = Object::new(CKO_SECRET_KEY);
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, value.to_vec()))
            .unwrap();
        obj
    }

    fn gcm_mech() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Regression test: `{:?}` formatting of a live `AesOperation` must
    /// not print the raw AES key, whether the operation is classic-mode
    /// or the `CKM_AES_KEY_WRAP*`-as-generic-cipher `key_wrap` variant
    /// (`AesKeyWrap` holds the key-encryption key). Same class of bug
    /// `awslc::x25519::X25519Key`'s own `debug_format_redacts_private_
    /// key_material` test guards against.
    #[test]
    fn debug_format_redacts_key_material() {
        let key_bytes = [0x77u8; 32];
        let key = test_key(&key_bytes);

        let enc_op =
            AesOperation::encrypt_new(&no_param_mech(CKM_AES_ECB), &key)
                .expect("encrypt_new");
        let debug_str = format!("{:?}", enc_op);
        assert!(!debug_str.contains(&format!("{:?}", key_bytes)));
        assert!(debug_str.contains("REDACTED"));

        let kw_mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_WRAP,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let kw_op =
            AesOperation::encrypt_new(&kw_mech, &key).expect("encrypt_new");
        let kw_debug_str = format!("{:?}", kw_op);
        assert!(!kw_debug_str.contains(&format!("{:?}", key_bytes)));
        assert!(kw_debug_str.contains("REDACTED"));
    }

    /// End-to-end exercise of the exact call sequence
    /// `src/encryption.rs`'s `aes_gcm_encrypt`/`aes_gcm_decrypt` use:
    /// `msg_*_init` -> `msg_*_len` -> one-shot `msg_encrypt`/`msg_decrypt`
    /// with a `CK_GCM_MESSAGE_PARAMS`, including a `CKG_GENERATE_RANDOM`
    /// IV on the encrypt side and reusing the generated IV/tag on the
    /// decrypt side, matching that module's exact usage pattern.
    #[test]
    fn msg_mode_round_trip_with_generated_iv() {
        let key = test_key(&[0x42u8; 32]);
        let aad = b"associated-data";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let mut iv = [0u8; 12];
        let mut tag = [0u8; 8];

        let mut enc_op = AesOperation::msg_encrypt_init(&gcm_mech(), &key)
            .expect("msg_encrypt_init");
        let clen = enc_op
            .msg_encryption_len(plaintext.len(), false)
            .expect("msg_encryption_len");
        assert_eq!(clen, plaintext.len());
        let mut ciphertext = vec![0u8; clen];

        let mut enc_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        let n = enc_op
            .msg_encrypt(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                plaintext,
                &mut ciphertext,
            )
            .expect("msg_encrypt");
        assert_eq!(n, plaintext.len());
        assert_ne!(&ciphertext[..], &plaintext[..]);
        // A real (non-zero) IV must have been generated and written back.
        assert_ne!(iv, [0u8; 12]);

        let mut dec_op = AesOperation::msg_decrypt_init(&gcm_mech(), &key)
            .expect("msg_decrypt_init");
        let plen = dec_op
            .msg_decryption_len(ciphertext.len(), false)
            .expect("msg_decryption_len");
        let mut recovered = vec![0u8; plen];

        let mut dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        let n = dec_op
            .msg_decrypt(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                &ciphertext,
                &mut recovered,
            )
            .expect("msg_decrypt");
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    /// End-to-end exercise of the real `Begin`/`Next`/`Final` API for GCM,
    /// on both encrypt and decrypt, with the plaintext/ciphertext split
    /// across multiple `Next` calls -- confirming this backend's
    /// buffer-then-finalize design (see `msg_encrypt_final`'s doc comment)
    /// round-trips correctly, not just the one-shot `msg_encrypt`/
    /// `msg_decrypt` path `msg_mode_round_trip_with_generated_iv` covers.
    #[test]
    fn msg_mode_gcm_begin_next_final_round_trip() {
        let key = test_key(&[0x11u8; 32]);
        let aad = b"begin-next-final-aad";
        let plaintext = b"the quick brown fox jumps over the lazy dog, again";

        let mut iv = [0x22u8; 12];
        let mut tag = [0u8; 16];
        let mut enc_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mut enc_op = AesOperation::msg_encrypt_init(&gcm_mech(), &key)
            .expect("msg_encrypt_init");
        enc_op
            .msg_encrypt_begin(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
            )
            .expect("msg_encrypt_begin");
        assert!(enc_op.busy());

        let (chunk1, chunk2) = plaintext.split_at(10);
        let mut throwaway = [0u8; 0];
        let n1 = enc_op
            .msg_encrypt_next(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                chunk1,
                &mut throwaway,
            )
            .expect("msg_encrypt_next chunk1");
        assert_eq!(n1, 0);
        let n2 = enc_op
            .msg_encrypt_next(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                &chunk2[..chunk2.len() - 5],
                &mut throwaway,
            )
            .expect("msg_encrypt_next chunk2");
        assert_eq!(n2, 0);

        let last_chunk = &chunk2[chunk2.len() - 5..];
        let mut ciphertext = vec![0u8; plaintext.len()];
        let n3 = enc_op
            .msg_encrypt_final(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                last_chunk,
                &mut ciphertext,
            )
            .expect("msg_encrypt_final");
        assert_eq!(n3, plaintext.len());
        assert_ne!(&ciphertext[..], &plaintext[..]);
        assert!(!enc_op.busy());

        // Decrypt back through the same Begin/Next/Final API, with a
        // different chunk split, and confirm it matches.
        let mut dec_op = AesOperation::msg_decrypt_init(&gcm_mech(), &key)
            .expect("msg_decrypt_init");
        let mut dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        dec_op
            .msg_decrypt_begin(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
            )
            .expect("msg_decrypt_begin");

        let (cchunk1, cchunk2) = ciphertext.split_at(30);
        let mut throwaway_p = [0u8; 0];
        dec_op
            .msg_decrypt_next(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                cchunk1,
                &mut throwaway_p,
            )
            .expect("msg_decrypt_next");

        let mut recovered = vec![0u8; plaintext.len()];
        let n = dec_op
            .msg_decrypt_final(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                cchunk2,
                &mut recovered,
            )
            .expect("msg_decrypt_final");
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
        assert!(!dec_op.busy());
    }

    /// `Final`'s buffer-too-small case must be non-fatal: the operation
    /// stays usable (`busy()` still true, not finalized), and since the
    /// size check runs before `plain` is appended to `msg_buffer`, that
    /// last chunk is never buffered on the failing attempt -- a retry must
    /// re-supply it (not empty) alongside a correctly-sized buffer.
    #[test]
    fn msg_encrypt_final_buffer_too_small_does_not_finalize() {
        let key = test_key(&[0x33u8; 32]);
        let plaintext = b"twelve bytes";
        let mut iv = [0x44u8; 12];
        let mut tag = [0u8; 16];
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mut op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        op.msg_encrypt_begin(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
        )
        .unwrap();

        let mut too_small = [0u8; 4];
        let err = op
            .msg_encrypt_final(
                &mut params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                plaintext,
                &mut too_small,
            )
            .expect_err("undersized buffer must fail");
        assert_eq!(err.rv(), CKR_BUFFER_TOO_SMALL);
        assert!(op.busy(), "buffer-too-small must not finalize the message");

        // The failed attempt's buffer-size check runs before appending
        // `plain` to msg_buffer, so it was never buffered -- the retry
        // must re-supply the same plaintext (not empty) alongside a
        // correctly-sized buffer.
        let mut ciphertext = vec![0u8; plaintext.len()];
        let n = op
            .msg_encrypt_final(
                &mut params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                plaintext,
                &mut ciphertext,
            )
            .expect("retry with correct buffer size");
        assert_eq!(n, plaintext.len());
        assert!(!op.busy());
    }

    #[test]
    fn msg_decrypt_rejects_tampered_tag() {
        let key = test_key(&[0x77u8; 32]);
        let aad = b"aad";
        let plaintext = b"secret data";

        let mut iv = [0u8; 12];
        let mut tag = [0u8; 8];
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut enc_op =
            AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        let mut enc_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        enc_op
            .msg_encrypt(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                plaintext,
                &mut ciphertext,
            )
            .unwrap();

        tag[0] ^= 0xFF;

        let mut dec_op =
            AesOperation::msg_decrypt_init(&gcm_mech(), &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let mut dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        let result = dec_op.msg_decrypt(
            &mut dec_params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            aad,
            &ciphertext,
            &mut recovered,
        );
        // A tampered/invalid AEAD tag must surface as
        // CKR_ENCRYPTED_DATA_INVALID, matching the reference implementation
        // (`src/ossl/aes.rs`'s `msg_decrypt_final` CKM_AES_GCM branch) and
        // the codebase-wide convention that CKR_SIGNATURE_INVALID is
        // reserved for MAC/CMAC/signature verification, not AEAD-decrypt
        // tag failures. It must NOT be the generic
        // `From<awslc::Error>`-mapped CKR_SIGNATURE_INVALID.
        let err = result.expect_err("tampered tag must be rejected");
        assert_eq!(err.rv(), CKR_ENCRYPTED_DATA_INVALID);
        assert_ne!(err.rv(), CKR_SIGNATURE_INVALID);
        // The trait contract finalizes the operation on any error other
        // than CKR_BUFFER_TOO_SMALL.
        assert!(dec_op.finalized());
    }

    /// A pure parameter-validation failure during `msg_encrypt`'s implicit
    /// Begin phase (before `self.in_use` is set) must NOT finalize the
    /// operation, mirroring `crate::ossl::aes`'s `init_msg_params`, which
    /// uses plain `Err(...)?` throughout instead of its own `op_err`-style
    /// finalizing helper -- see `setup_msg_encrypt_gcm`'s doc comment. This
    /// lets a caller retry `C_EncryptMessageBegin`/one-shot
    /// `C_EncryptMessage` with corrected parameters within the same
    /// `C_MessageEncryptInit` bracket. Only a failure once the operation is
    /// actually active (a real `Next`/`Final` crypto failure) finalizes.
    #[test]
    fn msg_encrypt_begin_validation_error_does_not_finalize() {
        let key = test_key(&[0x22u8; 32]);
        let mut iv = [0u8; 12];
        let mut tag = [0u8; 8];
        let plaintext = b"data";
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        // ulTagBits == 4 is invalid (must be in [8, 128]).
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 4,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert_eq!(
            result.expect_err("invalid ulTagBits must fail").rv(),
            CKR_MECHANISM_PARAM_INVALID
        );
        assert!(!op.finalized());

        // A retry with corrected parameters must still succeed.
        params.ulTagBits = (tag.len() * 8) as CK_ULONG;
        let result2 = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert!(result2.is_ok());
    }

    /// A `CKG_GENERATE_RANDOM` request for an IV shorter than
    /// `MIN_RANDOM_IV_BITS` (64 bits / 8 bytes) must be rejected, mirroring
    /// `crate::ossl::aes`'s equivalent check: an IV that short is not safe
    /// to generate at random.
    #[test]
    fn msg_encrypt_rejects_short_random_iv() {
        let key = test_key(&[0x55u8; 32]);
        // 4 bytes == 32 bits, below the 64-bit minimum.
        let mut iv = [0u8; 4];
        let mut tag = [0u8; 8];
        let plaintext = b"data";
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert_eq!(
            result
                .expect_err("too-short random IV must be rejected")
                .rv(),
            CKR_ARGUMENTS_BAD
        );
        // A Begin-phase validation failure (before self.in_use is set)
        // must not finalize the operation -- see
        // msg_encrypt_begin_validation_error_does_not_finalize.
        assert!(!op.finalized());
    }

    /// `CKR_BUFFER_TOO_SMALL` is the sole error that must NOT finalize the
    /// operation, so the caller can retry with a correctly-sized buffer.
    /// A successful retry does not finalize the operation either: PKCS#11
    /// allows several real `C_EncryptMessage` calls under one
    /// `C_MessageEncryptInit`/`C_MessageEncryptFinal` bracket, so only the
    /// explicit `MessageOperation::finalize()` call (`C_MessageEncryptFinal`'s
    /// counterpart) may set it -- see `impl MessageOperation for
    /// AesOperation`'s `finalize()` doc comment for why eagerly finalizing
    /// here would make that same explicit call unreachable.
    #[test]
    fn msg_encrypt_buffer_too_small_does_not_finalize() {
        let key = test_key(&[0x33u8; 32]);
        let mut iv = [0u8; 12];
        let mut tag = [0u8; 8];
        let plaintext = b"more data than the undersized buffer";
        let mut undersized = vec![0u8; 1];

        let mut op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut undersized,
        );
        assert_eq!(
            result.expect_err("undersized buffer must fail").rv(),
            CKR_BUFFER_TOO_SMALL
        );
        assert!(!op.finalized());

        // Retrying with a correctly-sized buffer on the same (still-live)
        // operation must succeed.
        let mut ciphertext = vec![0u8; plaintext.len()];
        let n = op
            .msg_encrypt(
                &mut params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                b"",
                plaintext,
                &mut ciphertext,
            )
            .expect("retry with correctly-sized buffer succeeds");
        assert_eq!(n, plaintext.len());
        assert!(!op.finalized());

        // Only the explicit C_MessageEncryptFinal counterpart finalizes it.
        op.finalize()
            .expect("finalize succeeds after a real message");
        assert!(op.finalized());
    }

    /// A message-mode `CK_MECHANISM` for `CKM_AES_CCM`, mirroring
    /// `gcm_mech()` above: `CK_CCM_MESSAGE_PARAMS` is supplied per-call to
    /// `msg_encrypt`/`msg_decrypt`, not via `pParameter` at init time.
    fn ccm_msg_mech() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_CCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// End-to-end exercise of `CKM_AES_CCM` through the message-mode API,
    /// mirroring `msg_mode_round_trip_with_generated_iv` above but for
    /// CCM's `CK_CCM_MESSAGE_PARAMS` (nonce/MAC instead of IV/tag), with a
    /// `CKG_GENERATE_RANDOM` nonce on the encrypt side.
    #[test]
    fn msg_mode_ccm_round_trip_with_generated_nonce() {
        let key = test_key(&[0x11u8; 16]);
        let aad = b"ccm-associated-data";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let mut nonce = [0u8; 12];
        let mut mac = [0u8; 8];

        let mut enc_op = AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key)
            .expect("msg_encrypt_init");
        let clen = enc_op
            .msg_encryption_len(plaintext.len(), false)
            .expect("msg_encryption_len");
        assert_eq!(clen, plaintext.len());
        let mut ciphertext = vec![0u8; clen];

        let mut enc_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_GENERATE_RANDOM,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let n = enc_op
            .msg_encrypt(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                plaintext,
                &mut ciphertext,
            )
            .expect("msg_encrypt");
        assert_eq!(n, plaintext.len());
        assert_ne!(&ciphertext[..], &plaintext[..]);
        // A real (non-zero) nonce must have been generated and written back.
        assert_ne!(nonce, [0u8; 12]);

        let mut dec_op = AesOperation::msg_decrypt_init(&ccm_msg_mech(), &key)
            .expect("msg_decrypt_init");
        let plen = dec_op
            .msg_decryption_len(ciphertext.len(), false)
            .expect("msg_decryption_len");
        let mut recovered = vec![0u8; plen];

        let mut dec_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: ciphertext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let n = dec_op
            .msg_decrypt(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                &ciphertext,
                &mut recovered,
            )
            .expect("msg_decrypt");
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    /// The CCM analogue of `msg_mode_gcm_begin_next_final_round_trip`. See
    /// `msg_encrypt_ccm_rejects_data_len_mismatch` for `ulDataLen`
    /// enforcement coverage (fatal/finalizing on mismatch, matching the
    /// reference, so it isn't interleaved with a successful round trip
    /// here).
    #[test]
    fn msg_mode_ccm_begin_next_final_round_trip() {
        let key = test_key(&[0x55u8; 16]);
        let aad = b"ccm-begin-next-final-aad";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let mut nonce = [0x66u8; 12];
        let mut mac = [0u8; 8];
        let mut enc_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };

        let mut enc_op = AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key)
            .expect("msg_encrypt_init");
        enc_op
            .msg_encrypt_begin(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
            )
            .expect("msg_encrypt_begin");

        let (chunk1, chunk2) = plaintext.split_at(20);
        let mut throwaway = [0u8; 0];
        let n1 = enc_op
            .msg_encrypt_next(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                chunk1,
                &mut throwaway,
            )
            .expect("msg_encrypt_next");
        assert_eq!(n1, 0);

        let mut ciphertext = vec![0u8; plaintext.len()];
        let n2 = enc_op
            .msg_encrypt_final(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                chunk2,
                &mut ciphertext,
            )
            .expect("msg_encrypt_final");
        assert_eq!(n2, plaintext.len());
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mut dec_op = AesOperation::msg_decrypt_init(&ccm_msg_mech(), &key)
            .expect("msg_decrypt_init");
        let mut dec_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: ciphertext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        dec_op
            .msg_decrypt_begin(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
            )
            .expect("msg_decrypt_begin");

        let (cchunk1, cchunk2) = ciphertext.split_at(15);
        let mut throwaway_p = [0u8; 0];
        dec_op
            .msg_decrypt_next(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                cchunk1,
                &mut throwaway_p,
            )
            .expect("msg_decrypt_next");

        let mut recovered = vec![0u8; plaintext.len()];
        let n = dec_op
            .msg_decrypt_final(
                &mut dec_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                cchunk2,
                &mut recovered,
            )
            .expect("msg_decrypt_final");
        assert_eq!(n, plaintext.len());
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    /// Mirrors `msg_decrypt_rejects_tampered_tag` above, for CCM: a
    /// tampered MAC must surface as `CKR_ENCRYPTED_DATA_INVALID`, not
    /// `CKR_SIGNATURE_INVALID`, and must finalize the operation.
    #[test]
    fn msg_decrypt_ccm_rejects_tampered_mac() {
        let key = test_key(&[0x77u8; 16]);
        let aad = b"aad";
        let plaintext = b"secret data";

        let mut nonce = [0u8; 12];
        let mut mac = [0u8; 8];
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut enc_op =
            AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key).unwrap();
        let mut enc_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_GENERATE_RANDOM,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        enc_op
            .msg_encrypt(
                &mut enc_params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad,
                plaintext,
                &mut ciphertext,
            )
            .unwrap();

        mac[0] ^= 0xFF;

        let mut dec_op =
            AesOperation::msg_decrypt_init(&ccm_msg_mech(), &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let mut dec_params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: ciphertext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let result = dec_op.msg_decrypt(
            &mut dec_params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
            aad,
            &ciphertext,
            &mut recovered,
        );
        let err = result.expect_err("tampered MAC must be rejected");
        assert_eq!(err.rv(), CKR_ENCRYPTED_DATA_INVALID);
        assert_ne!(err.rv(), CKR_SIGNATURE_INVALID);
        assert!(dec_op.finalized());
    }

    /// Parameter-validation rejection mirroring
    /// `msg_encrypt_rejects_short_random_iv` above: CCM's nonce length
    /// must be in `[7, 13]` (NIST SP 800-38C), matching
    /// `crate::ossl::aes::AesOperation::init_msg_params`'s `CKM_AES_CCM`
    /// arm. A 14-byte nonce is out of range and must be rejected with
    /// `CKR_MECHANISM_PARAM_INVALID`, without finalizing the operation
    /// (a Begin-phase validation failure, per
    /// `msg_encrypt_begin_validation_error_does_not_finalize`).
    #[test]
    fn msg_encrypt_ccm_rejects_out_of_range_nonce_len() {
        let key = test_key(&[0x55u8; 16]);
        // 14 bytes is above the 13-byte maximum nonce length for CCM.
        let mut nonce = [0u8; 14];
        let mut mac = [0u8; 8];
        let plaintext = b"data";
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut op =
            AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key).unwrap();
        let mut params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert_eq!(
            result
                .expect_err("out-of-range nonce length must be rejected")
                .rv(),
            CKR_MECHANISM_PARAM_INVALID
        );
        assert!(!op.finalized());
    }

    /// A too-short (32-bit) randomly generated CCM nonce must be rejected,
    /// mirroring `msg_encrypt_rejects_short_random_iv` above (also a
    /// Begin-phase validation failure that does not finalize).
    #[test]
    fn msg_encrypt_ccm_rejects_short_random_nonce() {
        let key = test_key(&[0x66u8; 16]);
        // 7 bytes == 56 bits, below the 64-bit minimum, but still a
        // spec-legal CCM nonce length ([7, 13]) on its own -- this
        // specifically exercises the random-generation floor, not the
        // nonce-length range check.
        let mut nonce = [0u8; 7];
        let mut mac = [0u8; 8];
        let plaintext = b"data";
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut op =
            AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key).unwrap();
        let mut params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_GENERATE_RANDOM,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert_eq!(
            result
                .expect_err("too-short random nonce must be rejected")
                .rv(),
            CKR_ARGUMENTS_BAD
        );
        assert!(!op.finalized());
    }

    /// A declared `ulDataLen` that doesn't match the actual plaintext
    /// length must be rejected with `CKR_DATA_LEN_RANGE`, mirroring
    /// `crate::ossl::aes::AesOperation::msg_encrypt_final`'s CCM branch.
    #[test]
    fn msg_encrypt_ccm_rejects_data_len_mismatch() {
        let key = test_key(&[0x99u8; 16]);
        let mut nonce = [0u8; 12];
        let mut mac = [0u8; 8];
        let plaintext = b"data";
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut op =
            AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key).unwrap();
        let mut params = CK_CCM_MESSAGE_PARAMS {
            // Declares one more byte than plaintext actually supplies.
            ulDataLen: (plaintext.len() + 1) as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        let result = op.msg_encrypt(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
            plaintext,
            &mut ciphertext,
        );
        assert_eq!(
            result
                .expect_err("data length mismatch must be rejected")
                .rv(),
            CKR_DATA_LEN_RANGE
        );
        assert!(op.finalized());
    }

    /// Message-mode CCM's declared `ulDataLen` is checked against
    /// `MAX_CCM_BUF` at Begin time, mirroring classic-mode CCM's own check
    /// (`ccm_classic_rejects_datalen_over_max_ccm_buf` above) -- this
    /// backend buffers the whole declared length internally either way.
    /// Unlike the classic-mode check, this one runs as pure Begin-phase
    /// parameter validation (before `self.in_use` is set), so it must NOT
    /// finalize the operation, matching
    /// `msg_encrypt_begin_validation_error_does_not_finalize`.
    #[test]
    fn msg_encrypt_ccm_rejects_datalen_over_max_ccm_buf() {
        let key = test_key(&[0xEBu8; 16]);
        let mut nonce = [0xECu8; 12];
        let mut mac = [0u8; 8];
        let mut params = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: (MAX_CCM_BUF + 1) as CK_ULONG,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };

        let mut op =
            AesOperation::msg_encrypt_init(&ccm_msg_mech(), &key).unwrap();
        let err = op
            .msg_encrypt_begin(
                &mut params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
                b"",
            )
            .expect_err("oversized ulDataLen must be rejected");
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
        assert!(!op.finalized());
    }

    /// Message-mode GCM has no declared total length to check up front
    /// (unlike CCM's `ulDataLen`), so its `MAX_CCM_BUF` cap is enforced
    /// directly against the accumulated buffer in `msg_encrypt_next`,
    /// mirroring classic-mode GCM's own check
    /// (`gcm_classic_rejects_buffer_over_max_ccm_buf` above). This runs
    /// once the operation is genuinely active, so -- unlike the CCM Begin-
    /// time check above -- it does finalize the operation, matching every
    /// other real (non-`CKR_BUFFER_TOO_SMALL`) `Next`/`Final` failure.
    #[test]
    fn msg_encrypt_gcm_rejects_buffer_over_max_ccm_buf() {
        let key = test_key(&[0xEDu8; 32]);
        let mut iv = [0xEEu8; 12];
        let mut tag = [0u8; 16];
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mut op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        op.msg_encrypt_begin(
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            b"",
        )
        .expect("msg_encrypt_begin");

        let oversized = vec![0u8; MAX_CCM_BUF + 1];
        let mut throwaway = [0u8; 0];
        let err = op
            .msg_encrypt_next(
                &mut params as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                &oversized,
                &mut throwaway,
            )
            .expect_err("oversized buffered plaintext must be rejected");
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
        assert!(op.finalized());
    }

    /// `msg_encrypt_init`/`msg_decrypt_init` must reject every mechanism
    /// other than `CKM_AES_GCM`/`CKM_AES_CCM`: PKCS#11's message-based
    /// encrypt/decrypt API has no defined parameter contract for the
    /// classic block-cipher-family mechanisms (ECB/CBC/CBC-PAD/CTR/OFB/
    /// CFB1/CFB8/CFB128), confirmed by `crate::aes::AES_MECHS[0]`/`[2]`
    /// (the mechanism-info entries `register_mechanisms` above assigns
    /// them) carrying no `CKF_MESSAGE_ENCRYPT`/`CKF_MESSAGE_DECRYPT` flag
    /// at all, and by `src/ossl/aes.rs`'s own message-mode implementation
    /// only ever matching `CKM_AES_GCM`/`CKM_AES_CCM`. `AesMechanism::
    /// msg_encryption_op`/`msg_decryption_op` (`src/aes.rs`) already gate
    /// on those flags before calling into this function at all in real
    /// PKCS#11 usage; this test locks in the same rejection at this
    /// function's own boundary, in case it's ever called directly.
    #[test]
    fn msg_init_rejects_non_aead_mechanisms() {
        let key = test_key(&[0x01u8; 16]);
        for ckm in &[
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_OFB,
            CKM_AES_CFB1,
            CKM_AES_CFB8,
            CKM_AES_CFB128,
        ] {
            let mech = CK_MECHANISM {
                mechanism: *ckm,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            assert_eq!(
                AesOperation::msg_encrypt_init(&mech, &key)
                    .expect_err("non-AEAD mechanism must be rejected")
                    .rv(),
                CKR_MECHANISM_INVALID
            );
            assert_eq!(
                AesOperation::msg_decrypt_init(&mech, &key)
                    .expect_err("non-AEAD mechanism must be rejected")
                    .rv(),
                CKR_MECHANISM_INVALID
            );
        }
    }

    /// `AesOperation.key` is a `SecretBuf` (see that type in `awslc-
    /// shared/cipher.rs`), which scrubs itself unconditionally whenever
    /// it drops -- including when `AesOperation` itself drops. That
    /// guarantee is exercised directly, in isolation, by `SecretBuf`'s
    /// own `secret_buf_tests` module; this test instead confirms
    /// `msg_encrypt_init` actually populates `key` with the real key
    /// bytes (not, say, an empty or zeroed buffer), which is the other
    /// half of the guarantee actually mattering here.
    #[test]
    fn msg_encrypt_init_populates_key() {
        let key_material = [0x99u8; 32];
        let key = test_key(&key_material);
        let op = AesOperation::msg_encrypt_init(&gcm_mech(), &key).unwrap();
        assert_eq!(&op.key[..], &key_material[..]);
    }

    #[test]
    fn non_message_paths_are_stubbed() {
        let key = test_key(&[0x11u8; 32]);
        // `gcm_mech()` has no real `CK_GCM_PARAMS`, so classic
        // `encrypt_new`/`decrypt_new` still fail here (with
        // CKR_ARGUMENTS_BAD, not CKR_MECHANISM_INVALID) -- see the
        // dedicated classic-mode tests below for the real (now
        // implemented) behavior with valid parameters.
        assert!(AesOperation::encrypt_new(&gcm_mech(), &key).is_err());
        assert!(AesOperation::decrypt_new(&gcm_mech(), &key).is_err());
        assert!(
            AesOperation::wrap(&gcm_mech(), &key, vec![0u8; 16], &mut [])
                .is_err()
        );
        assert!(AesOperation::unwrap(&gcm_mech(), &key, &[0u8; 16]).is_err());
        assert!(AesMacOperation::init(&gcm_mech(), &key, None).is_err());
        assert!(AesCmacOperation::init(&gcm_mech(), &key, None).is_err());
    }

    // ---- Classic (non-message) Encryption/Decryption ----

    fn cbc_like_mech(mechanism: CK_MECHANISM_TYPE, iv: &[u8]) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: iv.as_ptr() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        }
    }

    fn ecb_mech() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_ECB,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    fn ctr_mech(param: &CK_AES_CTR_PARAMS) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param as *const CK_AES_CTR_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        }
    }

    fn classic_gcm_mech(param: &CK_GCM_PARAMS) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: param as *const CK_GCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        }
    }

    fn ccm_mech(param: &CK_CCM_PARAMS) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_CCM,
            pParameter: param as *const CK_CCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
        }
    }

    /// Round-trips `plaintext` through `encrypt_new`/`decrypt_new` using
    /// a single one-shot `encrypt()`/`decrypt()` call each, and asserts
    /// the recovered plaintext matches. `mech_fn` is called twice (once
    /// per direction) since `CK_MECHANISM` isn't `Clone` and some modes
    /// (CBC/CBC-PAD/CTR/OFB/CFB*) require the SAME initial IV on both
    /// sides.
    fn one_shot_round_trip(
        key: &Object,
        mech_fn: impl Fn() -> CK_MECHANISM,
        plaintext: &[u8],
    ) {
        let mech = mech_fn();
        let mut enc_op =
            AesOperation::encrypt_new(&mech, key).expect("encrypt_new");
        let clen = enc_op
            .encryption_len(plaintext.len(), true)
            .expect("encryption_len");
        let mut ciphertext = vec![0u8; clen];
        let n = enc_op.encrypt(plaintext, &mut ciphertext).expect("encrypt");
        ciphertext.truncate(n);

        let mech = mech_fn();
        let mut dec_op =
            AesOperation::decrypt_new(&mech, key).expect("decrypt_new");
        let plen = dec_op
            .decryption_len(ciphertext.len(), true)
            .expect("decryption_len");
        let mut recovered = vec![0u8; plen];
        let n = dec_op
            .decrypt(&ciphertext, &mut recovered)
            .expect("decrypt");
        assert_eq!(&recovered[..n], plaintext);
    }

    #[test]
    fn ecb_round_trip() {
        let key = test_key(&[0x2Bu8; 16]);
        // Exactly two 16-byte blocks: ECB has no padding, input must be
        // block-aligned.
        let plaintext = b"0123456789ABCDEFFEDCBA9876543210";
        assert_eq!(plaintext.len() % AES_BLOCK_SIZE, 0);
        one_shot_round_trip(&key, ecb_mech, plaintext);
    }

    #[test]
    fn ecb_non_block_aligned_input_rejected() {
        let key = test_key(&[0x11u8; 16]);
        let mech = ecb_mech();
        let mut op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let plaintext = b"not sixteen"; // 11 bytes
        let mut cipher = vec![0u8; 32];
        let err = op.encrypt(plaintext, &mut cipher).unwrap_err();
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
    }

    #[test]
    fn cbc_round_trip_no_padding() {
        let key = test_key(&[0x11u8; 32]);
        let iv = [0x22u8; AES_BLOCK_SIZE];
        // Two full blocks.
        let plaintext = b"0123456789ABCDEFFEDCBA9876543210";
        assert_eq!(plaintext.len() % AES_BLOCK_SIZE, 0);
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CBC, &iv),
            plaintext,
        );
    }

    #[test]
    fn cbc_round_trip_aes192() {
        // Regression test for a bug where AES-192 (a 24-byte key) fell
        // through `awslc::cipher::cipher_mode_to_evp`'s `_` arm and
        // returned CKR_GENERAL_ERROR for every classic block-cipher mode.
        let key = test_key(&[0x99u8; 24]);
        let iv = [0xaau8; AES_BLOCK_SIZE];
        let plaintext = b"0123456789ABCDEFFEDCBA9876543210";
        assert_eq!(plaintext.len() % AES_BLOCK_SIZE, 0);
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CBC, &iv),
            plaintext,
        );
    }

    #[test]
    fn cbc_wrong_iv_length_rejected() {
        let key = test_key(&[0x11u8; 32]);
        let short_iv = [0x22u8; 8];
        let mech = cbc_like_mech(CKM_AES_CBC, &short_iv);
        let err = AesOperation::encrypt_new(&mech, &key).unwrap_err();
        assert_eq!(err.rv(), CKR_ARGUMENTS_BAD);
    }

    /// `classic_new`'s error paths (bad IV length, out-of-range AEAD
    /// parameters, `CKM_AES_CTS`, ...) must scrub the raw key bytes they
    /// briefly held before propagating the error. This used to require a
    /// dedicated `scrub_and_err` helper and a direct unit test for it
    /// (a plain `Vec<u8>` has no `Drop`-based scrubbing of its own,
    /// unlike the reference's `OsslSecret`); now that `keybytes` is a
    /// `SecretBuf` (see that type in `awslc/src/cipher.rs`), the same
    /// guarantee holds unconditionally on every exit path, already
    /// covered in isolation by `SecretBuf`'s own `secret_buf_tests`. This
    /// test instead just confirms `classic_new`'s bad-IV error path
    /// (covering both directions, unlike `cbc_wrong_iv_length_rejected`
    /// above, which only checks `encrypt_new`) still reports the correct
    /// `CK_RV`.
    #[test]
    fn cbc_wrong_iv_length_rejected_both_directions() {
        let key = test_key(&[0x11u8; 32]);
        let short_iv = [0x22u8; 8];
        let mech = cbc_like_mech(CKM_AES_CBC, &short_iv);
        let err = AesOperation::encrypt_new(&mech, &key).unwrap_err();
        assert_eq!(err.rv(), CKR_ARGUMENTS_BAD);
        let err = AesOperation::decrypt_new(&mech, &key).unwrap_err();
        assert_eq!(err.rv(), CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn cbc_pad_round_trip_non_block_aligned() {
        let key = test_key(&[0x33u8; 32]);
        let iv = [0x44u8; AES_BLOCK_SIZE];
        let plaintext = b"this message is not a multiple of the block size";
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CBC_PAD, &iv),
            plaintext,
        );
    }

    #[test]
    fn cbc_pad_round_trip_exact_multiple_of_block_size() {
        // PKCS#7 padding must still add a full extra pad block even when
        // the input is already block-aligned.
        let key = test_key(&[0x33u8; 32]);
        let iv = [0x44u8; AES_BLOCK_SIZE];
        let plaintext = [0x5Au8; AES_BLOCK_SIZE * 2];
        let mech = cbc_like_mech(CKM_AES_CBC_PAD, &iv);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let mut ciphertext = vec![0u8; AES_BLOCK_SIZE * 3];
        let n = enc_op.encrypt(&plaintext, &mut ciphertext).unwrap();
        assert_eq!(n, AES_BLOCK_SIZE * 3);

        let mech = cbc_like_mech(CKM_AES_CBC_PAD, &iv);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; AES_BLOCK_SIZE * 3];
        let n = dec_op.decrypt(&ciphertext[..n], &mut recovered).unwrap();
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn cbc_pad_multi_part_streaming_round_trip() {
        // Exercises encrypt_update/encrypt_final and decrypt_update/
        // decrypt_final directly (not the one-shot encrypt()/decrypt()),
        // across several unevenly-sized chunks, to cover the per-block
        // buffering (encrypt) and holdback (decrypt) logic.
        let key = test_key(&[0x55u8; 32]);
        let iv = [0x66u8; AES_BLOCK_SIZE];
        let plaintext = b"streaming CBC-PAD data across several unevenly sized update calls to exercise buffering";

        let mech = cbc_like_mech(CKM_AES_CBC_PAD, &iv);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let chunks: Vec<&[u8]> = vec![
            &plaintext[..5],
            &plaintext[5..20],
            &plaintext[20..21],
            &plaintext[21..],
        ];
        let mut ciphertext = Vec::new();
        for chunk in &chunks {
            let outlen = enc_op.encryption_len(chunk.len(), false).unwrap();
            let mut out = vec![0u8; outlen];
            let n = enc_op.encrypt_update(chunk, &mut out).unwrap();
            assert_eq!(n, outlen);
            ciphertext.extend_from_slice(&out[..n]);
        }
        let finlen = enc_op.encryption_len(0, true).unwrap();
        let mut fin = vec![0u8; finlen];
        let n = enc_op.encrypt_final(&mut fin).unwrap();
        ciphertext.extend_from_slice(&fin[..n]);

        let mech = cbc_like_mech(CKM_AES_CBC_PAD, &iv);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let dec_chunks: Vec<&[u8]> = vec![
            &ciphertext[..7],
            &ciphertext[7..22],
            &ciphertext[22..23],
            &ciphertext[23..],
        ];
        let mut recovered = Vec::new();
        for chunk in &dec_chunks {
            let outlen = dec_op.decryption_len(chunk.len(), false).unwrap();
            let mut out = vec![0u8; outlen];
            let n = dec_op.decrypt_update(chunk, &mut out).unwrap();
            assert_eq!(n, outlen);
            recovered.extend_from_slice(&out[..n]);
        }
        let finlen = dec_op.decryption_len(0, true).unwrap();
        let mut fin = vec![0u8; finlen];
        let n = dec_op.decrypt_final(&mut fin).unwrap();
        recovered.extend_from_slice(&fin[..n]);

        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[test]
    fn ctr_round_trip_streaming_unaligned_chunks() {
        let key = test_key(&[0x77u8; 32]);
        let param = CK_AES_CTR_PARAMS {
            ulCounterBits: 128,
            cb: [0x11u8; AES_BLOCK_SIZE],
        };
        let plaintext =
            b"counter mode plaintext streamed across unaligned chunk sizes";

        let mech = ctr_mech(&param);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let chunks: Vec<&[u8]> =
            vec![&plaintext[..3], &plaintext[3..10], &plaintext[10..]];
        let mut ciphertext = Vec::new();
        for chunk in &chunks {
            let mut out = vec![0u8; chunk.len()];
            let n = enc_op.encrypt_update(chunk, &mut out).unwrap();
            assert_eq!(n, chunk.len());
            ciphertext.extend_from_slice(&out[..n]);
        }
        let mut fin = vec![0u8; 0];
        enc_op.encrypt_final(&mut fin).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mech = ctr_mech(&param);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; ciphertext.len()];
        let n = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn ctr_counter_exhaustion_rejected() {
        // 9-bit counter starting one block away from wraparound: the
        // first block succeeds, the second must fail with
        // CKR_DATA_LEN_RANGE, mirroring src/tests/aes.rs's equivalent
        // OpenSSL-backend test.
        let key = test_key(&[0x22u8; 16]);
        let param = CK_AES_CTR_PARAMS {
            ulCounterBits: 9,
            cb: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0xFE,
            ],
        };
        let mech = ctr_mech(&param);
        let mut op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let data = [0xFFu8; AES_BLOCK_SIZE];
        let mut out = vec![0u8; AES_BLOCK_SIZE];
        let n = op.encrypt_update(&data, &mut out).unwrap();
        assert_eq!(n, AES_BLOCK_SIZE);

        let mut out2 = vec![0u8; AES_BLOCK_SIZE];
        let err = op.encrypt_update(&data, &mut out2).unwrap_err();
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
    }

    #[test]
    fn ofb_round_trip() {
        let key = test_key(&[0x88u8; 32]);
        let iv = [0x99u8; AES_BLOCK_SIZE];
        let plaintext = b"OFB mode stream cipher test data, any length";
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_OFB, &iv),
            plaintext,
        );
    }

    #[test]
    fn cfb128_round_trip() {
        let key = test_key(&[0xAAu8; 32]);
        let iv = [0xBBu8; AES_BLOCK_SIZE];
        let plaintext = b"CFB128 mode stream cipher test data, any length";
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CFB128, &iv),
            plaintext,
        );
    }

    #[test]
    fn cfb8_round_trip() {
        let key = test_key(&[0xCCu8; 32]);
        let iv = [0xDDu8; AES_BLOCK_SIZE];
        let plaintext = b"CFB8 test data";
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CFB8, &iv),
            plaintext,
        );
    }

    #[test]
    fn cfb1_round_trip() {
        let key = test_key(&[0xEEu8; 32]);
        let iv = [0xFFu8; AES_BLOCK_SIZE];
        let plaintext = b"CFB1 test";
        one_shot_round_trip(
            &key,
            || cbc_like_mech(CKM_AES_CFB1, &iv),
            plaintext,
        );
    }

    #[test]
    fn gcm_classic_round_trip_one_shot() {
        let key = test_key(&[0x12u8; 32]);
        let iv = [0x34u8; 12];
        let aad = b"classic gcm aad";
        let plaintext = b"classic (non-message) GCM plaintext";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        one_shot_round_trip(&key, || classic_gcm_mech(&param), plaintext);
    }

    /// GCM Test Case 2 from McGrew & Viega, "The Galois/Counter Mode of
    /// Operation" (the all-zero AES-128 key/IV/plaintext, no-AAD vector,
    /// widely reproduced as a NIST-aligned known-answer test in other
    /// implementations' test suites) -- pins an exact expected
    /// ciphertext+tag, unlike the self-consistency-only round trip above.
    #[test]
    fn gcm_classic_matches_test_case_2_known_answer_vector() {
        let key = test_key(&[0u8; 16]);
        let iv: [u8; 12] = [0u8; 12];
        let plaintext: [u8; 16] = [0u8; 16];
        let expected_ct: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2,
            0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67,
            0xb2, 0x12, 0x57, 0xbd, 0xdf,
        ];
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: std::ptr::null_mut(),
            ulAADLen: 0,
            ulTagBits: 128,
        };
        let mech = classic_gcm_mech(&param);
        let mut enc_op =
            AesOperation::encrypt_new(&mech, &key).expect("encrypt_new");
        let clen = enc_op
            .encryption_len(plaintext.len(), true)
            .expect("encryption_len");
        let mut ciphertext = vec![0u8; clen];
        let n = enc_op
            .encrypt(&plaintext, &mut ciphertext)
            .expect("encrypt");
        ciphertext.truncate(n);
        assert_eq!(ciphertext.len(), expected_ct.len() + expected_tag.len());
        assert_eq!(&ciphertext[..expected_ct.len()], &expected_ct[..]);
        assert_eq!(&ciphertext[expected_ct.len()..], &expected_tag[..]);
    }

    #[test]
    fn gcm_classic_multi_part_streaming() {
        // encrypt_update never emits output early in this backend (see
        // the module doc comment): every update call must return 0, and
        // encrypt_final must return the entire ciphertext + tag at once.
        let key = test_key(&[0x56u8; 32]);
        let iv = [0x78u8; 12];
        let aad = b"aad";
        let plaintext = b"multi part classic gcm plaintext data";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 96,
        };
        let tag_len = 12;

        let mech = classic_gcm_mech(&param);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let mut out1 = vec![0u8; 4];
        let n1 = enc_op.encrypt_update(&plaintext[..4], &mut out1).unwrap();
        assert_eq!(n1, 0, "GCM update must never emit early in this backend");
        let mut out2 = vec![0u8; plaintext.len() - 4];
        let n2 = enc_op.encrypt_update(&plaintext[4..], &mut out2).unwrap();
        assert_eq!(n2, 0);
        let finlen = enc_op.encryption_len(0, true).unwrap();
        assert_eq!(finlen, plaintext.len() + tag_len);
        let mut fin = vec![0u8; finlen];
        let n = enc_op.encrypt_final(&mut fin).unwrap();
        assert_eq!(n, finlen);

        let mech = classic_gcm_mech(&param);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let n = dec_op.decrypt(&fin[..n], &mut recovered).unwrap();
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn gcm_classic_decrypt_rejects_tampered_tag() {
        let key = test_key(&[0x9Au8; 32]);
        let iv = [0xBCu8; 12];
        let aad = b"aad";
        let plaintext = b"tamper-detect me";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mech = classic_gcm_mech(&param);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let clen = enc_op.encryption_len(plaintext.len(), true).unwrap();
        let mut ciphertext = vec![0u8; clen];
        let n = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext[n - 1] ^= 0xFF; // corrupt the tag's last byte

        let mech = classic_gcm_mech(&param);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let err = dec_op.decrypt(&ciphertext, &mut recovered).unwrap_err();
        assert_eq!(err.rv(), CKR_ENCRYPTED_DATA_INVALID);
        assert!(dec_op.finalized());
    }

    /// Classic (non-message) GCM buffers the *entire* message
    /// unconditionally (see the module-level doc comment) -- unlike CCM,
    /// which has a declared `ulDataLen` to check against, GCM has no
    /// upfront length at all, so `MAX_CCM_BUF` has to be enforced directly
    /// against the accumulated buffer in `classic_encrypt_update`. A
    /// single over-limit `encrypt_update` call is enough to trigger it
    /// (buffer starts empty).
    #[test]
    fn gcm_classic_rejects_buffer_over_max_ccm_buf() {
        let key = test_key(&[0xE5u8; 32]);
        let iv = [0xE6u8; 12];
        let aad = b"aad";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mech = classic_gcm_mech(&param);
        let mut op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let oversized = vec![0u8; MAX_CCM_BUF + 1];
        let mut out = vec![0u8; 0];
        let err = op.encrypt_update(&oversized, &mut out).unwrap_err();
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
        assert!(op.finalized());
    }

    /// Classic CCM's declared `ulDataLen` is checked against `MAX_CCM_BUF`
    /// up front (mirroring `crate::ossl::aes`'s own message-mode
    /// `MAX_CCM_BUF` check), so this rejects on the very first
    /// `encrypt_update` call regardless of how small that call's chunk is
    /// -- no multi-megabyte buffer actually needs to be allocated to
    /// exercise it -- though `encryption_len`'s own prediction for
    /// non-final CCM updates (`datalen + taglen`, unconditionally, so it
    /// can report the eventual output size to the caller up front) still
    /// requires `out` to be sized for the full declared length, or the
    /// generic buffer-too-small precheck in `encrypt_update` would fire
    /// first instead of the `MAX_CCM_BUF` check this test targets.
    #[test]
    fn ccm_classic_rejects_datalen_over_max_ccm_buf() {
        let key = test_key(&[0xE7u8; 32]);
        let nonce = [0xE8u8; 12];
        let aad = b"aad";
        let taglen = 8;
        let datalen = MAX_CCM_BUF + 1;
        let param = CK_CCM_PARAMS {
            ulDataLen: datalen as CK_ULONG,
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: taglen as CK_ULONG,
        };
        let mech = ccm_mech(&param);
        let mut op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let chunk = [0u8; 1];
        let mut out = vec![0u8; datalen + taglen];
        let err = op.encrypt_update(&chunk, &mut out).unwrap_err();
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
        assert!(op.finalized());
    }

    #[test]
    fn ccm_classic_round_trip_one_shot() {
        let key = test_key(&[0x21u8; 32]);
        let nonce = [0x43u8; 12];
        let aad = b"ccm aad";
        let plaintext = b"classic ccm plaintext";
        let param = CK_CCM_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: 8,
        };
        one_shot_round_trip(&key, || ccm_mech(&param), plaintext);
    }

    /// RFC 3610 "Packet Vector #1": a widely-reproduced AES-128 CCM
    /// known-answer vector (8-byte MAC, 13-byte nonce, 8-byte associated
    /// data, 23-byte payload) -- pins an exact expected ciphertext+MAC,
    /// unlike the self-consistency-only round trip above.
    #[test]
    fn ccm_classic_matches_rfc3610_packet_vector_1() {
        let key = test_key(&[
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
            0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        ]);
        let nonce: [u8; 13] = [
            0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5,
        ];
        let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let plaintext: [u8; 23] = [
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E,
        ];
        let param = CK_CCM_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: 8,
        };
        let mech = ccm_mech(&param);
        let mut enc_op =
            AesOperation::encrypt_new(&mech, &key).expect("encrypt_new");
        let clen = enc_op
            .encryption_len(plaintext.len(), true)
            .expect("encryption_len");
        let mut ciphertext = vec![0u8; clen];
        let n = enc_op
            .encrypt(&plaintext, &mut ciphertext)
            .expect("encrypt");
        ciphertext.truncate(n);
        let expected: [u8; 31] = [
            0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2, 0xF0, 0x66, 0xD0,
            0xC2, 0xC0, 0xF9, 0x89, 0x80, 0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3,
            0x84, 0x17, 0xE8, 0xD1, 0x2C, 0xFD, 0xF9, 0x26, 0xE0,
        ];
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn ccm_classic_multi_part_streaming_emits_ciphertext_on_completion() {
        // Matches src/tests/aes.rs's OpenSSL-backend expectations: a
        // partial update (not yet reaching the declared ulDataLen) emits
        // nothing, the update that completes it emits the FULL
        // ciphertext immediately, and encrypt_final emits only the tag.
        let key = test_key(&[0x65u8; 32]);
        let nonce = [0x87u8; 12];
        let aad = b"aad";
        let plaintext = b"01234567";
        let tag_len = 4usize;
        let param = CK_CCM_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: tag_len as CK_ULONG,
        };

        let mech = ccm_mech(&param);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        // encryption_len's non-final CCM prediction is the reference's own
        // conservative constant (datalen + taglen, regardless of how much
        // of that a given call will actually emit) -- size every update
        // buffer from it, exactly as a real caller would.
        let part1 = &plaintext[..plaintext.len() - 1];
        let out1_len = enc_op.encryption_len(part1.len(), false).unwrap();
        let mut out1 = vec![0u8; out1_len];
        let n1 = enc_op.encrypt_update(part1, &mut out1).unwrap();
        assert_eq!(n1, 0);

        let part2 = &plaintext[plaintext.len() - 1..];
        let out2_len = enc_op.encryption_len(part2.len(), false).unwrap();
        let mut out2 = vec![0u8; out2_len];
        let n2 = enc_op.encrypt_update(part2, &mut out2).unwrap();
        assert_eq!(n2, plaintext.len());

        let finlen = enc_op.encryption_len(0, true).unwrap();
        let mut fin = vec![0u8; finlen];
        let n3 = enc_op.encrypt_final(&mut fin).unwrap();
        assert_eq!(n3, tag_len);

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&out2[..n2]);
        ciphertext.extend_from_slice(&fin[..n3]);

        let mech = ccm_mech(&param);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let n = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        assert_eq!(&recovered[..n], &plaintext[..]);
    }

    #[test]
    fn ccm_classic_decrypt_rejects_tampered_tag() {
        let key = test_key(&[0xA1u8; 32]);
        let nonce = [0xB2u8; 12];
        let aad = b"aad";
        let plaintext = b"authenticate me";
        let param = CK_CCM_PARAMS {
            ulDataLen: plaintext.len() as CK_ULONG,
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: 8,
        };
        let mech = ccm_mech(&param);
        let mut enc_op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let clen = enc_op.encryption_len(plaintext.len(), true).unwrap();
        let mut ciphertext = vec![0u8; clen];
        let n = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext[n - 1] ^= 0xFF;

        let mech = ccm_mech(&param);
        let mut dec_op = AesOperation::decrypt_new(&mech, &key).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let err = dec_op.decrypt(&ciphertext, &mut recovered).unwrap_err();
        assert_eq!(err.rv(), CKR_ENCRYPTED_DATA_INVALID);
        assert!(dec_op.finalized());
    }

    #[test]
    fn cts_is_not_supported() {
        let key = test_key(&[0x11u8; 32]);
        let iv = [0x22u8; AES_BLOCK_SIZE];
        let mech = cbc_like_mech(CKM_AES_CTS, &iv);
        let err = AesOperation::encrypt_new(&mech, &key).unwrap_err();
        assert_eq!(err.rv(), CKR_MECHANISM_INVALID);
        let err = AesOperation::decrypt_new(&mech, &key).unwrap_err();
        assert_eq!(err.rv(), CKR_MECHANISM_INVALID);
    }

    /// `CKM_AES_ECB` (and every other classic cipher mechanism) is
    /// advertised with `CKF_WRAP`/`CKF_UNWRAP` via the shared
    /// `crate::aes::AES_MECHS` table, and `wrap`/`unwrap` support it via
    /// `wrap_cipher`/`unwrap_cipher`, matching the reference
    /// `crate::ossl::aes::AesOperation::wrap`. A single AES block needs no
    /// zero-padding, so this also confirms wrap/unwrap round-trip through
    /// `AesOperation::encrypt_new`/`decrypt_new` directly (not just via
    /// PKCS#11's own `C_Encrypt`/`C_Decrypt`, exercised by
    /// `src/tests/keys.rs`'s `test_rsa_key`/`test_rsa_key_unwrap_vector`).
    #[test]
    fn cipher_mechanism_wrap_round_trip() {
        let kek = test_key(&[0x11u8; 32]);
        let mech = ecb_mech();
        let keydata = vec![0x42u8; AES_BLOCK_SIZE];
        let mut output = vec![0u8; AES_BLOCK_SIZE * 2];

        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut output)
            .unwrap();
        assert_eq!(n, AES_BLOCK_SIZE);
        assert_ne!(&output[..n], keydata.as_slice());

        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &output[..n]).unwrap();
        assert_eq!(unwrapped, keydata);
    }

    /// `CKM_AES_CBC`/`_ECB` require block-aligned input for the classic
    /// (non-padded) `Encrypt`/`Decrypt` path -- `wrap_cipher` must zero-pad
    /// `keydata` up to a block boundary first, matching the reference.
    #[test]
    fn cipher_mechanism_wrap_pads_to_block_boundary() {
        let kek = test_key(&[0x22u8; 32]);
        let mech = ecb_mech();
        let keydata = vec![0x7Fu8; AES_BLOCK_SIZE + 3];
        let mut output = vec![0u8; AES_BLOCK_SIZE * 2];

        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut output)
            .unwrap();
        assert_eq!(n, AES_BLOCK_SIZE * 2);

        // Unwrap recovers the zero-padded (not the original) length --
        // CKM_AES_ECB/_CBC are not padding-aware, so the caller is
        // responsible for knowing/trimming the real length, same as the
        // reference backend.
        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &output[..n]).unwrap();
        assert_eq!(unwrapped.len(), AES_BLOCK_SIZE * 2);
        assert_eq!(&unwrapped[..keydata.len()], keydata.as_slice());
        assert!(unwrapped[keydata.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn cbc_encrypt_update_buffer_too_small_does_not_finalize() {
        let key = test_key(&[0x11u8; 32]);
        let iv = [0x22u8; AES_BLOCK_SIZE];
        let mech = cbc_like_mech(CKM_AES_CBC, &iv);
        let mut op = AesOperation::encrypt_new(&mech, &key).unwrap();
        let plaintext = [0x33u8; AES_BLOCK_SIZE * 2];
        let mut undersized = vec![0u8; AES_BLOCK_SIZE]; // needs 32
        let err = op.encrypt(&plaintext, &mut undersized).unwrap_err();
        assert_eq!(err.rv(), CKR_BUFFER_TOO_SMALL);
        assert!(!op.finalized());

        let mut ok_buf = vec![0u8; AES_BLOCK_SIZE * 2];
        let n = op.encrypt(&plaintext, &mut ok_buf).unwrap();
        assert_eq!(n, AES_BLOCK_SIZE * 2);
    }

    /// Classic-mode counterpart of `msg_encrypt_init_populates_key`: `key`
    /// scrubbing itself on drop is `SecretBuf`'s own guarantee (see that
    /// test's doc comment); this confirms `encrypt_new`'s `classic_new`
    /// path also populates `key` with the real key bytes.
    #[test]
    fn encrypt_new_populates_key() {
        let key_material = [0x77u8; 32];
        let key = test_key(&key_material);
        let iv = [0x22u8; AES_BLOCK_SIZE];
        let mech = cbc_like_mech(CKM_AES_CBC, &iv);
        let op = AesOperation::encrypt_new(&mech, &key).unwrap();
        assert_eq!(&op.key[..], &key_material[..]);
    }

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    #[test]
    fn key_wrap_round_trip() {
        let kek = test_key(&[0x99u8; 32]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP);
        // 16 bytes -- a multiple of the 8-byte semiblock, as CKM_AES_KEY_WRAP
        // (unlike PKCS7/KWP) requires.
        let keydata = vec![0x11u8; 16];

        let needed =
            AesOperation::wrap(&mech, &kek, keydata.clone(), &mut []).unwrap();
        assert_eq!(needed, 24);

        let mut wrapped = vec![0u8; needed];
        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut wrapped)
            .unwrap();
        assert_eq!(n, 24);
        assert_ne!(&wrapped[..n], &keydata[..]);

        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &wrapped[..n]).expect("unwrap");
        assert_eq!(unwrapped, keydata);
    }

    #[test]
    fn key_wrap_pkcs7_round_trip_odd_length() {
        let kek = test_key(&[0x88u8; 24]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP_PKCS7);
        // Deliberately not a multiple of 8 bytes, exercising PKCS7 padding.
        let keydata = b"odd-len-key-material".to_vec();
        assert_ne!(keydata.len() % AES_KW_SEMIBLOCK, 0);

        let needed =
            AesOperation::wrap(&mech, &kek, keydata.clone(), &mut []).unwrap();
        let mut wrapped = vec![0u8; needed];
        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut wrapped)
            .unwrap();
        assert_eq!(n, needed);

        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &wrapped[..n]).expect("unwrap");
        assert_eq!(unwrapped, keydata);
    }

    #[test]
    fn key_wrap_pkcs7_round_trip_block_aligned() {
        // Block-aligned plaintext must still get a full 8-byte pad block
        // (PKCS7's usual "always pad" rule), unlike plain CKM_AES_KEY_WRAP.
        let kek = test_key(&[0x88u8; 16]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP_PKCS7);
        let keydata = vec![0x55u8; 16];

        let needed =
            AesOperation::wrap(&mech, &kek, keydata.clone(), &mut []).unwrap();
        // 16 bytes of data + a full 8-byte pad block + 8-byte KW overhead.
        assert_eq!(needed, 32);
        let mut wrapped = vec![0u8; needed];
        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut wrapped)
            .unwrap();
        assert_eq!(n, needed);

        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &wrapped[..n]).expect("unwrap");
        assert_eq!(unwrapped, keydata);
    }

    #[test]
    fn key_wrap_kwp_round_trip_arbitrary_length() {
        let kek = test_key(&[0x33u8; 32]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP_KWP);
        let keydata = b"arbitrary length, not block aligned at all".to_vec();

        let needed =
            AesOperation::wrap(&mech, &kek, keydata.clone(), &mut []).unwrap();
        let mut wrapped = vec![0u8; needed];
        let n = AesOperation::wrap(&mech, &kek, keydata.clone(), &mut wrapped)
            .unwrap();
        assert_eq!(n, needed);

        let unwrapped =
            AesOperation::unwrap(&mech, &kek, &wrapped[..n]).expect("unwrap");
        assert_eq!(unwrapped, keydata);
    }

    #[test]
    fn key_wrap_unwrap_rejects_tampered_ciphertext() {
        let kek = test_key(&[0x44u8; 16]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP);
        let keydata = vec![0x22u8; 16];
        let needed =
            AesOperation::wrap(&mech, &kek, keydata.clone(), &mut []).unwrap();
        let mut wrapped = vec![0u8; needed];
        AesOperation::wrap(&mech, &kek, keydata.clone(), &mut wrapped).unwrap();
        wrapped[0] ^= 0xff;

        let err = AesOperation::unwrap(&mech, &kek, &wrapped).unwrap_err();
        assert_eq!(err.rv(), CKR_ENCRYPTED_DATA_INVALID);
    }

    #[test]
    fn key_wrap_rejects_output_too_small() {
        let kek = test_key(&[0x44u8; 16]);
        let mech = no_param_mech(CKM_AES_KEY_WRAP);
        let keydata = vec![0x22u8; 16];
        let mut undersized = vec![0u8; 8]; // needs 24
        let err = AesOperation::wrap(&mech, &kek, keydata, &mut undersized)
            .unwrap_err();
        assert_eq!(err.rv(), CKR_BUFFER_TOO_SMALL);
    }

    // ---- AES-CMAC / AES-MAC (CBC-MAC) ----

    fn general_mech(
        mechanism: CK_MECHANISM_TYPE,
        len: &CK_MAC_GENERAL_PARAMS,
    ) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: len as *const CK_MAC_GENERAL_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_MAC_GENERAL_PARAMS>()
                as CK_ULONG,
        }
    }

    /// RFC 4493 Section 4, Example 1: AES-128 CMAC of the empty message.
    /// The same known-answer vector already validated at the
    /// `awslc::mac::Cmac` layer -- here exercised through the
    /// full `AesCmacOperation::init` + `Sign` PKCS#11-facing surface.
    #[test]
    fn cmac_matches_rfc4493_empty_message() {
        let key = test_key(&[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ]);
        let expected = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d,
            0x12, 0x9b, 0x75, 0x67, 0x46,
        ];
        let mut op =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .expect("init");
        let mut mac = [0u8; 16];
        Sign::sign(&mut op, b"", &mut mac).expect("sign");
        assert_eq!(mac, expected);

        // Also confirm verification round-trips against the same vector,
        // via both the two-argument `Verify` trait and the
        // signature-provided-at-init `VerifySignature` trait.
        let mut vop =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .expect("init");
        Verify::verify(&mut vop, b"", &expected).expect("verify");

        let mut vsop = AesCmacOperation::init(
            &no_param_mech(CKM_AES_CMAC),
            &key,
            Some(&expected),
        )
        .expect("init with signature");
        VerifySignature::verify(&mut vsop, b"").expect("verify_signature");
    }

    /// Multi-part `sign_update`/`sign_final` must match the one-shot
    /// `sign` result for the same message, and the CMAC must round-trip
    /// through `Verify` -- exercised over a message spanning several AES
    /// blocks (CMAC's own block chaining, not just the single-block RFC
    /// vector above).
    #[test]
    fn cmac_multipart_matches_one_shot_and_verifies() {
        let key = test_key(&[0x2bu8; 16]);
        let data = b"some message data that is longer than one block";

        let mut one_shot_op =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .unwrap();
        let mut one_shot_mac = [0u8; 16];
        Sign::sign(&mut one_shot_op, data, &mut one_shot_mac).unwrap();

        let mut multipart_op =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .unwrap();
        Sign::sign_update(&mut multipart_op, &data[..10]).unwrap();
        Sign::sign_update(&mut multipart_op, &data[10..]).unwrap();
        let mut multipart_mac = [0u8; 16];
        Sign::sign_final(&mut multipart_op, &mut multipart_mac).unwrap();
        assert_eq!(one_shot_mac, multipart_mac);

        let mut vop =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .unwrap();
        Verify::verify(&mut vop, data, &one_shot_mac).expect("verify");
    }

    #[test]
    fn cmac_general_truncates_output_and_verifies() {
        let key = test_key(&[0x2bu8; 16]);
        let data = b"some message data";

        let mut full_op =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .unwrap();
        let mut full_mac = [0u8; 16];
        Sign::sign(&mut full_op, data, &mut full_mac).unwrap();

        let len: CK_MAC_GENERAL_PARAMS = 4;
        let gen_mech = general_mech(CKM_AES_CMAC_GENERAL, &len);
        let mut gen_op = AesCmacOperation::init(&gen_mech, &key, None).unwrap();
        let mut truncated = [0u8; 4];
        Sign::sign(&mut gen_op, data, &mut truncated).unwrap();
        assert_eq!(&truncated[..], &full_mac[..4]);

        let mut vop = AesCmacOperation::init(&gen_mech, &key, None).unwrap();
        Verify::verify(&mut vop, data, &truncated).expect("verify");
    }

    #[test]
    fn cmac_general_rejects_length_over_block_size() {
        let key = test_key(&[0x2bu8; 16]);
        let len: CK_MAC_GENERAL_PARAMS = 17;
        let mech = general_mech(CKM_AES_CMAC_GENERAL, &len);
        let err = AesCmacOperation::init(&mech, &key, None).unwrap_err();
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn cmac_rejects_bad_key_length() {
        let key = test_key(&[0x11u8; 10]);
        let err =
            AesCmacOperation::init(&no_param_mech(CKM_AES_CMAC), &key, None)
                .unwrap_err();
        assert_eq!(err.rv(), CKR_KEY_INDIGESTIBLE);
    }

    #[test]
    fn cmac_rejects_nonzero_params_for_plain_mechanism() {
        let key = test_key(&[0x2bu8; 16]);
        let len: CK_MAC_GENERAL_PARAMS = 8;
        // Reusing CKM_AES_CMAC (not _GENERAL) with a parameter attached
        // must be rejected.
        let mech = general_mech(CKM_AES_CMAC, &len);
        let err = AesCmacOperation::init(&mech, &key, None).unwrap_err();
        assert_eq!(err.rv(), CKR_ARGUMENTS_BAD);
    }

    /// `CKM_AES_MAC` is CBC-MAC: sign then verify with the same key/data
    /// must succeed, and tampering either the data or the signature must
    /// fail verification. The message intentionally spans several AES
    /// blocks plus a trailing partial block, to exercise the zero-padded
    /// last block in `AesMacOperation::finalize`.
    #[test]
    fn mac_round_trip_sign_and_verify() {
        let key = test_key(&[0x5au8; 16]);
        let data = b"this is a message longer than one AES block!!!";

        let mut sign_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init sign");
        let mut mac = [0u8; AES_BLOCK_SIZE / 2];
        Sign::sign(&mut sign_op, data, &mut mac).expect("sign");

        let mut verify_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init verify");
        Verify::verify(&mut verify_op, data, &mac).expect("verify");

        // Also exercise the signature-provided-at-init VerifySignature path.
        let mut vsop = AesMacOperation::init(
            &no_param_mech(CKM_AES_MAC),
            &key,
            Some(&mac),
        )
        .expect("init with signature");
        VerifySignature::verify(&mut vsop, data).expect("verify_signature");
    }

    #[test]
    fn mac_verify_rejects_tampered_data() {
        let key = test_key(&[0x5au8; 16]);
        let data = b"this is a message longer than one AES block!!!";

        let mut sign_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init sign");
        let mut mac = [0u8; AES_BLOCK_SIZE / 2];
        Sign::sign(&mut sign_op, data, &mut mac).expect("sign");

        let mut tampered = data.to_vec();
        tampered[0] ^= 0xff;

        let mut verify_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init verify");
        let err = Verify::verify(&mut verify_op, &tampered, &mac)
            .expect_err("tampered data must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    #[test]
    fn mac_verify_rejects_tampered_signature() {
        let key = test_key(&[0x5au8; 16]);
        let data = b"exactly16bytes!!";

        let mut sign_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init sign");
        let mut mac = [0u8; AES_BLOCK_SIZE / 2];
        Sign::sign(&mut sign_op, data, &mut mac).expect("sign");
        mac[0] ^= 0xff;

        let mut verify_op =
            AesMacOperation::init(&no_param_mech(CKM_AES_MAC), &key, None)
                .expect("init verify");
        let err = Verify::verify(&mut verify_op, data, &mac)
            .expect_err("tampered signature must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    #[test]
    fn mac_general_truncates_output_and_verifies() {
        let key = test_key(&[0x5au8; 16]);
        let data = b"data spanning more than one block of CBC-MAC!!";

        let len: CK_MAC_GENERAL_PARAMS = 6;
        let mech = general_mech(CKM_AES_MAC_GENERAL, &len);
        let mut sign_op = AesMacOperation::init(&mech, &key, None).unwrap();
        let mut mac = [0u8; 6];
        Sign::sign(&mut sign_op, data, &mut mac).unwrap();

        let mut verify_op = AesMacOperation::init(&mech, &key, None).unwrap();
        Verify::verify(&mut verify_op, data, &mac).expect("verify");
    }

    #[test]
    fn mac_general_rejects_length_over_block_size() {
        let key = test_key(&[0x5au8; 16]);
        let len: CK_MAC_GENERAL_PARAMS = 17;
        let mech = general_mech(CKM_AES_MAC_GENERAL, &len);
        let err = AesMacOperation::init(&mech, &key, None).unwrap_err();
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn mac_rejects_nonzero_params_for_plain_mechanism() {
        let key = test_key(&[0x5au8; 16]);
        let len: CK_MAC_GENERAL_PARAMS = 8;
        let mech = general_mech(CKM_AES_MAC, &len);
        let err = AesMacOperation::init(&mech, &key, None).unwrap_err();
        assert_eq!(err.rv(), CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn cmac_and_mac_register_their_mechanisms() {
        let mut mechs = Mechanisms::new();
        AesCmacOperation::register_mechanisms(&mut mechs);
        AesMacOperation::register_mechanisms(&mut mechs);
        assert!(mechs.get(CKM_AES_CMAC).is_ok());
        assert!(mechs.get(CKM_AES_CMAC_GENERAL).is_ok());
        assert!(mechs.get(CKM_AES_MAC).is_ok());
        assert!(mechs.get(CKM_AES_MAC_GENERAL).is_ok());
    }

    /// Regression test for a real, previously-unnoticed gap: `AesOperation::
    /// register_mechanisms` never registered `CKM_AES_KEY_GEN` for this
    /// backend (across Phases 1-2), so `C_GenerateKey(CKM_AES_KEY_GEN, ...)`
    /// would fail with "mechanism not found" -- AES keys could be imported
    /// but never generated. This drives the full path end-to-end (register
    /// -> look up -> `Mechanism::generate_key`), the same way
    /// `crate::aes::AesMechanism::generate_key` is reached from
    /// `C_GenerateKey` in production, without needing a full `Token`/
    /// `Session` (this trait method only touches its own private
    /// `AES_KEY_FACTORY` and the thread-local CSPRNG, neither of which
    /// needs the `Mechanisms`/`ObjectFactories` arguments it also takes --
    /// mirroring how `msg_mode_round_trip_with_generated_iv` above drives
    /// message-mode end-to-end without a full token either). This test
    /// fails (RED) without the `CKM_AES_KEY_GEN` registration line in
    /// `register_mechanisms` and passes (GREEN) with it.
    #[test]
    fn key_gen_is_registered_and_produces_a_usable_key() {
        use crate::mechanism::Mechanism;
        use crate::object::ObjectFactories;

        let mut mechs = Mechanisms::new();
        AesOperation::register_mechanisms(&mut mechs);

        let entry = mechs
            .get(CKM_AES_KEY_GEN)
            .expect("CKM_AES_KEY_GEN must be registered for the awslc backend");
        assert_ne!(
            entry.info().flags & CKF_GENERATE,
            0,
            "CKM_AES_KEY_GEN's registered mechanism must carry CKF_GENERATE"
        );

        let mut value_len: CK_ULONG = 32;
        let template = [CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let no_mechs = Mechanisms::new();
        let no_factories = ObjectFactories::new();
        let mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let key = entry
            .generate_key(&mech, &template, &no_mechs, &no_factories)
            .expect("generate_key must succeed for CKM_AES_KEY_GEN");
        assert_eq!(key.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_AES);
        assert_eq!(key.get_attr_as_bytes(CKA_VALUE).unwrap().len(), 32);
    }
}
