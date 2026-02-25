// Copyright 2024-2026 Simo Sorce
// See LICENSE.txt file for terms

use std::cell::Cell;
use std::ffi::{c_char, c_int};

use crate::config::FipsBehavior;
use crate::error::Result;
use crate::mechanism::Mechanisms;
use crate::object::{ObjectFactories, ObjectType};
use crate::pkcs11::*;

use ossl::{bindings, fips};

pub(crate) mod indicators;
pub(crate) mod kats;

pub const FIPS_VALIDATION_OBJ: CK_ULONG = 1;

/// Sets the FIPS module into the error state
pub fn set_fips_error_state() {
    fips::set_error_state();
}

/// Checks if the FIPS module is in an error state
pub fn check_fips_state_ok() -> bool {
    return fips::check_state_ok();
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
#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
pub static INITIALIZE_FIPS: extern "C" fn() = init_fips;

#[unsafe(no_mangle)]
pub extern "C" fn init_fips() {
    fips::set_fips_indicator_callback(Some(fips_indicator_callback));
}

/* The Openssl FIPS indicator callback is inadequate for easily
 * accessing individual indicators in the context of a single
 * operation because it is tied to the general library context,
 * which can be shared across multiple threads in an application.
 * Therefore the only way to make this work in a thread safe way
 * is to use thread local variables */
thread_local! {
    static FIPS_INDICATOR: Cell<u32> = Cell::new(0);
}

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

/// This structure represent whether a service execetuion is approved.
/// It has access to the internal OpenSSL fips indicator callbacks
/// and can query the fips indicators to establish if a non-approved
/// operation occurred.
#[derive(Debug)]
pub struct FipsApproval {
    approved: Option<bool>,
}

impl FipsApproval {
    /// clear the thread local fips indicator so that any
    /// new indicator trigger can be detected
    fn clear_indicator() {
        FIPS_INDICATOR.set(0);
    }

    /// Checks thread local fips indicator to see if it has
    /// been triggered
    fn check_indicator() -> bool {
        FIPS_INDICATOR.get() != 0
    }

    /// Clears indicators and creates a new FipsApproval object
    pub fn init() -> FipsApproval {
        Self::clear_indicator();
        FipsApproval { approved: None }
    }

    /// Resets FipsApproval status
    pub fn reset(&mut self) {
        self.approved = None;
    }

    /// Clears indicators

    pub fn clear(&self) {
        Self::clear_indicator();
    }

    /// Check if any indicator has triggered and updates
    /// internal status if that happened.
    pub fn update(&mut self) {
        if Self::check_indicator() {
            /* The indicator was set, therefore there was an unapproved use */
            self.approved = Some(false);
        }
    }

    /// Resutrns current approval status
    pub fn approval(&self) -> Option<bool> {
        self.approved
    }

    /// Check if operation is approved, returns true only
    /// if the operation has been positively marked as
    /// approved.
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

    /// Finalizes approval status, generaly used after the last operation
    /// for the service.
    pub fn finalize(&mut self) {
        self.update();
        /* this is the last check, mark approval as true if not set so far */
        self.set(true);
    }
}
