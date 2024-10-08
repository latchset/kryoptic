// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::interface::CKO_VALIDATION;
use crate::mechanism::Mechanisms;
use crate::object::{ObjectFactories, ObjectType};
use crate::token::Token;

pub(crate) mod indicators;

pub fn token_init(token: &mut Token) -> Result<()> {
    indicators::insert_fips_validation(token)
}

pub fn register(_: &mut Mechanisms, ot: &mut ObjectFactories) {
    ot.add_factory(
        ObjectType::new(CKO_VALIDATION, 0),
        &indicators::VALIDATION_FACTORY,
    );
}
