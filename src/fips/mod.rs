// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::interface::CKO_VALIDATION;
use crate::mechanism::Mechanisms;
use crate::object::{ObjectFactories, ObjectType};
use crate::ossl::fips;
use crate::token::Token;

pub(crate) mod indicators;

pub fn set_fips_error_state() {
    fips::set_error_state();
}

pub fn check_fips_state_ok() -> bool {
    return fips::check_state_ok();
}

pub fn token_init(token: &mut Token) -> Result<()> {
    indicators::insert_fips_validation(token)
}

pub fn register(_: &mut Mechanisms, ot: &mut ObjectFactories) {
    ot.add_factory(
        ObjectType::new(CKO_VALIDATION, 0),
        &indicators::VALIDATION_FACTORY,
    );
}
