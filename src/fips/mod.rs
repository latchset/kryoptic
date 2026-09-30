// Copyright 2024-2026 Simo Sorce
// See LICENSE.txt file for terms

use crate::config::FipsBehavior;
use crate::error::Result;
use crate::mechanism::Mechanisms;
use crate::object::{ObjectFactories, ObjectType};
use crate::pkcs11::*;

#[cfg(feature = "ossl-backend")]
use std::cell::Cell;
#[cfg(feature = "ossl-backend")]
use std::ffi::{c_char, c_int};

#[cfg(feature = "ossl-backend")]
use ossl::{bindings, fips};

pub(crate) mod indicators;
pub(crate) mod kats;

#[cfg(feature = "ossl-backend")]
pub(crate) mod provider;

pub const FIPS_VALIDATION_OBJ: CK_ULONG = 1;

/// Sets the FIPS module into the error state
#[cfg(feature = "ossl-backend")]
pub fn set_fips_error_state() {
    fips::set_error_state();
}

/// Checks if the FIPS module is in an error state
#[cfg(feature = "ossl-backend")]
pub fn check_fips_state_ok() -> bool {
    return fips::check_state_ok();
}

/// Latches kryoptic's own KAT (`src/fips/kats.rs`) failure state under
/// awslc-fips. This is unrelated to AWS-LC's own self-test, which runs at
/// library load and aborts the process on failure -- this is specifically
/// for kryoptic's own HMAC/TLS-PRF known-answer tests, whose only caller
/// is `FIPSSelftest::fail()`.
#[cfg(feature = "awslc-fips")]
static FIPS_ERROR_STATE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Sets the FIPS module into the error state (kryoptic's own KAT failure
/// latch -- see `FIPS_ERROR_STATE`'s doc comment).
#[cfg(feature = "awslc-fips")]
pub fn set_fips_error_state() {
    FIPS_ERROR_STATE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Checks if the FIPS module is in an error state (kryoptic's own KAT
/// failure latch -- see `FIPS_ERROR_STATE`'s doc comment).
#[cfg(feature = "awslc-fips")]
pub fn check_fips_state_ok() -> bool {
    !FIPS_ERROR_STATE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Helper function to register the validation object factory
pub fn register(_: &mut Mechanisms, ot: &mut ObjectFactories) {
    ot.add_factory(
        ObjectType::new(CKO_VALIDATION, 0),
        &(*indicators::VALIDATION_FACTORY),
    );
}

/// Check a key template and based on the requested `FipsBehavior`
/// checks whether the CKA_SENSITIVE attribute contains an appropriate value
pub fn check_key_template(
    template: &[CK_ATTRIBUTE],
    fips_opts: &FipsBehavior,
) -> Result<()> {
    if !fips_opts.keys_always_sensitive {
        return Ok(());
    }

    match template.iter().find(|a| a.type_ == CKA_SENSITIVE) {
        Some(a) => {
            if a.to_bool()? == false {
                Err(CKR_ATTRIBUTE_VALUE_INVALID)?
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

/* Ensure we provide a callback for fips indicators */
#[cfg(feature = "ossl-backend")]
#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
pub static INITIALIZE_FIPS: extern "C" fn() = init_fips;

#[cfg(feature = "ossl-backend")]
#[unsafe(no_mangle)]
pub extern "C" fn init_fips() {
    provider::set_fips_indicator_callback(Some(fips_indicator_callback));
}

/* The Openssl FIPS indicator callback is inadequate for easily
 * accessing individual indicators in the context of a single
 * operation because it is tied to the general library context,
 * which can be shared across multiple threads in an application.
 * Therefore the only way to make this work in a thread safe way
 * is to use thread local variables */
#[cfg(feature = "ossl-backend")]
thread_local! {
    static FIPS_INDICATOR: Cell<u32> = Cell::new(0);
}

#[cfg(feature = "ossl-backend")]
unsafe extern "C" fn fips_indicator_callback(
    _type_: *const c_char,
    _desc: *const c_char,
    _params: *const bindings::OSSL_PARAM,
) -> c_int {
    /* We ignore type, desc, params, for now, and just register
     * if a change in state occurred.
     *
     * We could track individual events in the callback, but
     * a) it is really hard to know what they are because the
     *    "type" is an arbitrary string and you need to go and
     *    find in the specific openssl fips provider sources to
     *    figure out what it is...
     * b) it is expensive as it ends up having to do a bunch
     *    of string compares, and based on that then modify
     *    some slot in a preallocated vector ...
     *
     * Within the context of a thread only one operation at
     * a time is performed, so, as long as the code correctly
     * resets the indicator before an operation is started and
     * immediately checks it at the end, tracking the status in
     * th operation context, it can get away with tracking
     * everything in a single per-thread variable and count on
     * the serial nature of code executing within a thread.
     *
     * Note that the callback is called only when the
     * underlying OpenSSL code believes there was an unapproved
     * condition. In strict mode the callback is not called and
     * the underlying function fails directly.
     */

    /* Set the indicator up, this means there was an unapproved
     * use. */
    FIPS_INDICATOR.set(1);

    /* Returning 1, allows OpenSSL to continue the operation.
     * Unless and until we implement a strict FIPS mode we never
     * want to cause a failure for an unapproved use, so we just
     * return all ok, FIPS_INDICATOR will allow us to propagate the
     * fact that the operation was unapproved by setting PKCS#11
     * indicators */
    return 1;
}

/// This structure represents whether a service execution is approved.
/// On `ossl-backend`, it has access to the internal OpenSSL fips
/// indicator callbacks and queries them to establish if a non-approved
/// operation occurred. On `awslc-fips`, it polls AWS-LC's
/// `FIPS_service_indicator_before_call`/`after_call` counter instead --
/// the two models have opposite polarity (OpenSSL signals "something bad
/// happened"; AWS-LC signals "something good happened").
#[derive(Debug)]
pub struct FipsApproval {
    approved: Option<bool>,
    #[cfg(feature = "awslc-fips")]
    before: u64,
}

impl FipsApproval {
    /// clear the thread local fips indicator so that any
    /// new indicator trigger can be detected
    #[cfg(feature = "ossl-backend")]
    fn clear_indicator() {
        FIPS_INDICATOR.set(0);
    }

    /// Checks thread local fips indicator to see if it has
    /// been triggered
    #[cfg(feature = "ossl-backend")]
    fn check_indicator() -> bool {
        FIPS_INDICATOR.get() != 0
    }

    /// Clears indicators and creates a new FipsApproval object
    #[cfg(feature = "ossl-backend")]
    pub fn init() -> FipsApproval {
        Self::clear_indicator();
        FipsApproval { approved: None }
    }

    /// Creates a new FipsApproval object, snapshotting the counter now so
    /// that a caller who calls `update()` directly after `init()` (the
    /// established pattern in `src/ossl/*.rs`, e.g. `src/ossl/rsa.rs`'s
    /// `encdec_new`/`sigver_new`) gets a correct answer even without an
    /// intervening `clear()` -- mirroring how `ossl-backend`'s `init()`
    /// also calls `clear_indicator()` for the same reason.
    #[cfg(feature = "awslc-fips")]
    pub fn init() -> FipsApproval {
        FipsApproval {
            approved: None,
            before: unsafe {
                aws_lc_fips_sys::FIPS_service_indicator_before_call()
            },
        }
    }

    /// Resets FipsApproval status
    pub fn reset(&mut self) {
        self.approved = None;
    }

    /// Clears indicators
    #[cfg(feature = "ossl-backend")]
    pub fn clear(&self) {
        Self::clear_indicator();
    }

    /// Snapshots AWS-LC's service-indicator counter before the chunk of
    /// work about to be bracketed.
    #[cfg(feature = "awslc-fips")]
    pub fn clear(&mut self) {
        self.before =
            unsafe { aws_lc_fips_sys::FIPS_service_indicator_before_call() };
    }

    /// Check if any indicator has triggered and updates
    /// internal status if that happened.
    #[cfg(feature = "ossl-backend")]
    pub fn update(&mut self) {
        if Self::check_indicator() {
            /* The indicator was set, therefore there was an unapproved use */
            self.approved = Some(false);
        }
    }

    /// Reads AWS-LC's service-indicator counter after the bracketed chunk
    /// of work and resolves approval for that chunk: the counter moves
    /// if and only if an approved service was called. Uses `set()`'s
    /// one-way ratchet, so a chunk with a mix of approved/unapproved
    /// steps still resolves correctly as long as each step gets its own
    /// `clear()`/`update()` pair.
    #[cfg(feature = "awslc-fips")]
    pub fn update(&mut self) {
        let after =
            unsafe { aws_lc_fips_sys::FIPS_service_indicator_after_call() };
        self.set(self.before != after);
    }

    /// Resutrns current approval status
    pub fn approval(&self) -> Option<bool> {
        self.approved
    }

    /// Check if operation is approved, returns true only
    /// if the operation has been positively marked as
    /// approved.
    #[allow(dead_code)]
    pub fn is_approved(&self) -> bool {
        if self.approved.is_some_and(|b| b == true) {
            return true;
        }
        return false;
    }

    /// Check if operation is not approved, returns true only
    /// if the operation has been positively marked as not
    /// approved.
    pub fn is_not_approved(&self) -> bool {
        if self.approved.is_some_and(|b| b == false) {
            return true;
        }
        return false;
    }

    /// Sets approval status.
    /// Note: approval can only go from true -> false
    /// A non-approved operation cannot be marked approved later.
    pub fn set(&mut self, b: bool) {
        if self.approved.is_some_and(|b| b == false) {
            return;
        }
        self.approved = Some(b);
    }

    /// Finalizes approval status, generally used after the last operation
    /// for the service.
    pub fn finalize(&mut self) {
        self.update();
        /* this is the last check, mark approval as true if not set so far */
        self.set(true);
    }
}

#[cfg(all(test, feature = "awslc-fips"))]
mod awslc_fips_tests {
    use super::FipsApproval;
    use crate::lowlevel::cipher::AesGcm;

    #[test]
    fn approved_operation_is_recorded_as_approved() {
        // AesGcm::new(key: &[u8], tag_len: usize) -> Result<AesGcm, Error>;
        // seal/open(&self, nonce, aad, ..., out) -> Result<usize, Error>
        // (see awslc/src/cipher.rs).
        //
        // AWS-LC's service indicator only credits AES-GCM as an approved
        // service on the *decrypt* path when the caller supplies the nonce:
        // per SP 800-38D §8.2.2, external-IV encryption is not itself
        // approved (only internally-generated IVs are for the encrypt
        // direction), so `AEAD_GCM_verify_service_indicator()` is only
        // called from `aead_aes_gcm_open_gather()`, not from
        // `aead_aes_gcm_seal_scatter()` (see aws-lc's
        // crypto/fipsmodule/cipher/e_aes.c). This test therefore brackets
        // `open()`, not `seal()`, to observe the counter move.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm::new(&key, 16).unwrap();

        let mut ct = [0u8; 32];
        let ct_len = cipher.seal(&nonce, &[], &[0u8; 16], &mut ct).unwrap();

        let mut approval = FipsApproval::init();
        approval.clear();

        let mut pt = [0u8; 16];
        cipher
            .open(&nonce, &[], &ct[..16], &ct[16..ct_len], &mut pt)
            .unwrap();

        approval.update();
        assert_eq!(approval.approval(), Some(true));
    }

    #[test]
    fn unapproved_operation_stays_unapproved_even_after_a_later_approved_one() {
        // seal() with an external nonce is NOT approved (see the comment on
        // the test above); open() IS approved. This proves both that an
        // unapproved step is correctly detected, and that FipsApproval's
        // one-way ratchet (see `set()`) doesn't let a later approved step
        // flip an already-unapproved result back to true.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm::new(&key, 16).unwrap();
        let mut approval = FipsApproval::init();

        approval.clear();
        let mut ct = [0u8; 32];
        let ct_len = cipher.seal(&nonce, &[], &[0u8; 16], &mut ct).unwrap();
        approval.update();
        assert_eq!(approval.approval(), Some(false));

        approval.clear();
        let mut pt = [0u8; 16];
        cipher
            .open(&nonce, &[], &ct[..16], &ct[16..ct_len], &mut pt)
            .unwrap();
        approval.update();
        assert_eq!(
            approval.approval(),
            Some(false),
            "an unapproved step must permanently latch approval to false, even after a later approved step"
        );
    }

    #[test]
    fn kbkdf_ctr_hmac_is_recorded_as_approved() {
        // KBKDF_ctr_hmac(out_key, out_len, digest, secret, secret_len,
        // info, info_len) -> c_int (see awslc/src/kbkdf.rs). Confirms
        // AWS-LC's service indicator actually credits
        // this call as approved for an HMAC-SHA256 PRF -- verified
        // empirically here rather than assumed, before relying on the same
        // clear()/update() bracket shape in
        // `crate::awslc::kbkdf::Sp800Operation::derive`.
        use crate::lowlevel::digest::DigestAlg;

        let key = [0x42u8; 16];
        let info = [0x01u8, 0x02, 0x03];
        let mut out = [0u8; 32];

        let mut approval = FipsApproval::init();
        approval.clear();
        crate::lowlevel::kbkdf::kbkdf_ctr_hmac(
            DigestAlg::Sha2_256,
            &key,
            &info,
            &mut out,
        )
        .unwrap();
        approval.update();
        assert_eq!(approval.approval(), Some(true));
    }
}
