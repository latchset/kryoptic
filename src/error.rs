// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::error;
use std::fmt;

use super::interface;

use serde_json;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    origin: Option<Box<dyn error::Error>>,
    errmsg: Option<String>,
    ckrv: interface::CK_RV,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ErrorKind {
    /* A Cryptoki-style error, see ckrv Error field */
    CkError,
    /* The attribute was not found, see errmsg */
    AttributeNotFound,
    /* Other error, see origin */
    Nested,
}

impl Error {
    pub fn ck_rv(ckrv: interface::CK_RV) -> Error {
        Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: None,
            ckrv: ckrv,
        }
    }

    pub fn ck_rv_from_error<E>(ckrv: interface::CK_RV, error: E) -> Error
    where
        E: Into<Box<dyn error::Error>>,
    {
        Error {
            kind: ErrorKind::CkError,
            origin: Some(error.into()),
            errmsg: None,
            ckrv: ckrv,
        }
    }

    pub fn ck_rv_with_errmsg(ckrv: interface::CK_RV, errmsg: String) -> Error {
        Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: Some(errmsg),
            ckrv: ckrv,
        }
    }

    pub fn not_found(errmsg: String) -> Error {
        Error {
            kind: ErrorKind::AttributeNotFound,
            origin: None,
            errmsg: Some(errmsg),
            ckrv: interface::CKR_GENERAL_ERROR,
        }
    }

    pub fn other_error<E>(error: E) -> Error
    where
        E: Into<Box<dyn error::Error>>,
    {
        Error {
            kind: ErrorKind::Nested,
            origin: Some(error.into()),
            errmsg: None,
            ckrv: interface::CKR_GENERAL_ERROR,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn attr_not_found(&self) -> bool {
        return self.kind == ErrorKind::AttributeNotFound;
    }

    pub fn rv(&self) -> interface::CK_RV {
        self.ckrv
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::CkError => {
                if let Some(ref e) = self.errmsg {
                    write!(f, "{}", e)
                } else {
                    match self.ckrv {
                        interface::CKR_GENERAL_ERROR => {
                            write!(f, std::stringify!(CKR_GENERAL_ERROR))
                        }
                        interface::CKR_ATTRIBUTE_TYPE_INVALID => {
                            write!(f, "CKR_ATTRIBUTE_TYPE_INVALID")
                        }
                        _ => write!(f, "{}", self.ckrv),
                    }
                }
            }
            ErrorKind::AttributeNotFound => write!(
                f,
                "attribute not found: {}",
                self.errmsg.as_ref().unwrap()
            ),
            ErrorKind::Nested => self.origin.as_ref().unwrap().fmt(f),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::other_error(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Error {
        Error::other_error(error)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(error: std::num::TryFromIntError) -> Error {
        Error::other_error(error)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(error: std::convert::Infallible) -> Error {
        Error::other_error(error)
    }
}

#[macro_export]
macro_rules! some_or_err {
    ($action:expr) => {
        if let Some(ref x) = $action {
            x
        } else {
            return Err(error::Error::ck_rv(interface::CKR_GENERAL_ERROR));
        }
    };
    (mut $action:expr) => {
        if let Some(ref mut x) = $action {
            x
        } else {
            return Err(error::Error::ck_rv(interface::CKR_GENERAL_ERROR));
        }
    };
}

#[macro_export]
macro_rules! err_rv {
    ($ck_err:expr) => {
        Err(error::Error::ck_rv($ck_err))
    };
}

#[macro_export]
macro_rules! err_not_found {
    ($err_str:expr) => {
        Err(error::Error::not_found($err_str))
    };
}

#[macro_export]
macro_rules! to_rv {
    ($ck_err:expr) => {
        error::Error::ck_rv($ck_err)
    };
}
