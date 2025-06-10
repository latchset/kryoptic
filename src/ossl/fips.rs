// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use ossl::fips::*;

fn clear_ossl_fips_indicator() {
    fips_indicator().set(0);
}

fn ossl_fips_indicator_is_set() -> bool {
    if fips_indicator().get() == 0 {
        return false;
    }
    return true;
}

fn fips_approval(fips_approved: &mut Option<bool>, finalize: bool) {
    if ossl_fips_indicator_is_set() {
        /* The indicator was set, therefore there was an unapproved use */
        *fips_approved = Some(false);
    }
    if finalize {
        /* this is the last check, mark approval as true if not set so far */
        if fips_approved.is_none() {
            *fips_approved = Some(true);
        }
    }
}

pub fn fips_approval_init_checks(fips_approved: &mut Option<bool>) {
    *fips_approved = None;
    clear_ossl_fips_indicator();
}

pub fn fips_approval_prep_check() {
    clear_ossl_fips_indicator();
}

pub fn fips_approval_check(fips_approved: &mut Option<bool>) {
    fips_approval(fips_approved, false);
}

pub fn fips_approval_finalize(fips_approved: &mut Option<bool>) {
    fips_approval(fips_approved, true);
}
