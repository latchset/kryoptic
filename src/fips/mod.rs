// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::config::FipsBehavior;
use crate::error::Result;
use crate::mechanism::Mechanisms;
use crate::object::{ObjectFactories, ObjectType};
use crate::pkcs11::*;

use ossl::fips;

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
