// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();
pub const CK_BBOOL_SIZE: usize = std::mem::size_of::<CK_BBOOL>();

macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as CK_VOID_PTR,
            ulValueLen: $length as CK_ULONG,
        }
    };
}

macro_rules! ret_or_panic {
    ($ret:expr) => {
        match $ret {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        }
    };
}
