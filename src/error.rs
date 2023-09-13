// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use serde_json;
use std::{error::Error, fmt};

use super::interface;

pub type KResult<T> = Result<T, KError>;

#[derive(Debug, Clone)]
pub struct CkRvError {
    pub rv: interface::CK_RV,
}

impl Error for CkRvError {}

impl fmt::Display for CkRvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.rv {
            interface::CKR_GENERAL_ERROR => write!(f, "CKR_GENERAL_ERROR"),
            interface::CKR_ATTRIBUTE_TYPE_INVALID => {
                write!(f, "CKR_ATTRIBUTE_TYPE_INVALID")
            }
            _ => write!(f, "unknown error"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttributeNotFound {
    pub s: String,
}

impl Error for AttributeNotFound {}

impl fmt::Display for AttributeNotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} not found", self.s)
    }
}

#[derive(Debug)]
pub enum KError {
    RvError(CkRvError),
    NotFound(AttributeNotFound),
    FileError(std::io::Error),
    JsonError(serde_json::error::Error),
}

impl fmt::Display for KError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KError::RvError(e) => write!(f, "CK_RV error: {}", e),
            KError::NotFound(e) => write!(f, "attribute not found {}", e),
            KError::FileError(e) => write!(f, "file error {}", e),
            KError::JsonError(e) => write!(f, "json parsing error {}", e),
        }
    }
}

#[macro_export]
macro_rules! err_rv {
    ($ck_err:expr) => {
        Err(KError::RvError(error::CkRvError { rv: $ck_err }))
    };
}

#[macro_export]
macro_rules! err_not_found {
    ($err_str:expr) => {
        Err(KError::NotFound(error::AttributeNotFound { s: $err_str }))
    };
}
