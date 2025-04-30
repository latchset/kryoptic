// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::error;
use std::fmt;

use crate::interface;

use asn1;
use serde_json;

/// The Result type used within the project, wraps
/// errors via the custom Error enum
pub type Result<T> = std::result::Result<T, Error>;

/// The project's error object
#[derive(Debug)]
pub struct Error {
    /// The error kind
    kind: ErrorKind,
    /// The originating error, if a mapping occurred
    origin: Option<Box<dyn error::Error>>,
    /// The error message string if set
    errmsg: Option<String>,
    /// Use only by ErrorKind::BufferTooSmall, indicates the
    /// required buffer size if the function is called again
    reqsize: usize,
    /// The PKCS#11 CK_RV error code to be returned to the application
    ckrv: interface::CK_RV,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A Cryptoki-style error, see ckrv Error field
    CkError,
    /// The attribute was not found, see errmsg
    AttributeNotFound,
    /// This error is used to indicate a provided buffer is too small
    BufferTooSmall,
    /// Other error, see origin
    Nested,
}

impl Error {
    /// Creates an error that represents a PKCS#11 Error code
    pub fn ck_rv(ckrv: interface::CK_RV) -> Error {
        Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: None,
            reqsize: 0,
            ckrv: ckrv,
        }
    }

    /// Creates an error that represents a PKCS#11 Error code, and stores
    /// the originating error code that was mapped to this error code
    pub fn ck_rv_from_error<E>(ckrv: interface::CK_RV, error: E) -> Error
    where
        E: Into<Box<dyn error::Error>>,
    {
        Error {
            kind: ErrorKind::CkError,
            origin: Some(error.into()),
            errmsg: None,
            reqsize: 0,
            ckrv: ckrv,
        }
    }

    /// Creates an error that represents a PKCS#11 Error code, and includes
    /// an error message
    pub fn ck_rv_with_errmsg(ckrv: interface::CK_RV, errmsg: String) -> Error {
        Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: Some(errmsg),
            reqsize: 0,
            ckrv: ckrv,
        }
    }

    /// Creates an AttributeNotFound error, and includes an error message
    pub fn not_found(errmsg: String) -> Error {
        Error {
            kind: ErrorKind::AttributeNotFound,
            origin: None,
            errmsg: Some(errmsg),
            reqsize: 0,
            ckrv: interface::CKR_GENERAL_ERROR,
        }
    }

    /// Creates an general (unspecified) error message from a previous error
    pub fn other_error<E>(error: E) -> Error
    where
        E: Into<Box<dyn error::Error>>,
    {
        Error {
            kind: ErrorKind::Nested,
            origin: Some(error.into()),
            errmsg: None,
            reqsize: 0,
            ckrv: interface::CKR_GENERAL_ERROR,
        }
    }

    /// Creates a BufferTooSmall error and set the required buffer size
    pub fn buf_too_small(reqsize: usize) -> Error {
        Error {
            kind: ErrorKind::BufferTooSmall,
            origin: None,
            errmsg: None,
            reqsize: reqsize,
            ckrv: interface::CKR_BUFFER_TOO_SMALL,
        }
    }

    /// Returns the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Check if this is a AttributeNotFound error
    pub fn attr_not_found(&self) -> bool {
        return self.kind == ErrorKind::AttributeNotFound;
    }

    /// Returns the associated PKCS#11 Error code
    pub fn rv(&self) -> interface::CK_RV {
        self.ckrv
    }

    /// Returns the associated required buffer size
    pub fn reqsize(&self) -> usize {
        self.reqsize
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
            ErrorKind::BufferTooSmall => {
                write!(f, "Buffer Too Small, required size: {}", self.reqsize)
            }
            ErrorKind::Nested => self.origin.as_ref().unwrap().fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    /// Maps a Std IoError to a generic error
    fn from(error: std::io::Error) -> Error {
        Error::other_error(error)
    }
}

impl From<serde_json::Error> for Error {
    /// Maps a Serde Json Error to a generic error
    fn from(error: serde_json::Error) -> Error {
        Error::other_error(error)
    }
}

impl From<std::num::TryFromIntError> for Error {
    /// Maps an integer conversion error to a generic error
    fn from(error: std::num::TryFromIntError) -> Error {
        Error::other_error(error)
    }
}

impl From<std::convert::Infallible> for Error {
    /// Maps an infallible error to a generic error
    fn from(error: std::convert::Infallible) -> Error {
        Error::other_error(error)
    }
}

impl From<interface::CK_RV> for Error {
    /// Maps a naked PKCS#11 Error code to an Error
    fn from(error: interface::CK_RV) -> Error {
        Error::ck_rv(error)
    }
}

impl From<asn1::ParseError> for Error {
    /// Maps a ASN.1 parsing error to a generic error
    fn from(error: asn1::ParseError) -> Error {
        Error::other_error(error)
    }
}

impl From<std::num::ParseIntError> for Error {
    /// Maps an integer parsing error to a generic error
    fn from(error: std::num::ParseIntError) -> Error {
        Error::other_error(error)
    }
}

impl From<asn1::WriteError> for Error {
    /// Maps a write error to a generic error
    fn from(error: asn1::WriteError) -> Error {
        Error::other_error(error)
    }
}

impl From<Vec<u8>> for Error {
    /// Consumes a vector and generates a BufferTooSmall error
    /// with its length as the requested length
    fn from(v: Vec<u8>) -> Error {
        Error::buf_too_small(v.len())
    }
}

use std::array::TryFromSliceError;
impl From<TryFromSliceError> for Error {
    /// Maps an error to manipulate a slice to a generic error
    fn from(error: TryFromSliceError) -> Error {
        Error::other_error(error)
    }
}

/// Returns a general error for empty Options
#[allow(unused_macros)]
macro_rules! some_or_err {
    ($action:expr) => {
        if let Some(ref x) = $action {
            x
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
    };
    (mut $action:expr) => {
        if let Some(ref mut x) = $action {
            x
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
    };
}
#[allow(unused_imports)]
pub(crate) use some_or_err;

/// Helper to return a CKR_GENERAL_ERROR error
#[allow(dead_code)]
pub fn general_error<E>(error: E) -> Error
where
    E: Into<Box<dyn error::Error>>,
{
    Error::ck_rv_from_error(interface::CKR_GENERAL_ERROR, error)
}

/// Helper to return a CKR_DEVICE_ERROR error
#[allow(dead_code)]
pub fn device_error<E>(error: E) -> Error
where
    E: Into<Box<dyn error::Error>>,
{
    Error::ck_rv_from_error(interface::CKR_DEVICE_ERROR, error)
}

/// Helper to return a CKR_ARGUMENTS_BAD error
pub fn arg_bad<E>(error: E) -> Error
where
    E: Into<Box<dyn error::Error>>,
{
    Error::ck_rv_from_error(interface::CKR_ARGUMENTS_BAD, error)
}

/// Helper to map an Error to a PKCS#11 Error code error
macro_rules! map_err {
    ($map:expr, $err:tt) => {{
        use crate::error::Error;
        $map.map_err(|e| Error::ck_rv_from_error($err, e))
    }};
}
pub(crate) use map_err;
