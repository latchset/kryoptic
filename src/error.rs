// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements functions to manage errors

use std::error;
use std::fmt;

use crate::pkcs11::*;

use asn1;
use ossl;
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
    ckrv: CK_RV,
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

macro_rules! trace_err {
    ($err:expr) => {{
        let e = $err;
        #[cfg(feature = "log")]
        if e.ckrv != CKR_OK {
            use log::error;
            error!("{}", &e);
        }
        e
    }};
}

impl Error {
    /// Creates an error that represents a PKCS#11 Error code
    pub fn ck_rv(ckrv: CK_RV) -> Error {
        trace_err!(Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: None,
            reqsize: 0,
            ckrv: ckrv,
        })
    }

    /// Creates an error that represents a PKCS#11 Error code, and stores
    /// the originating error code that was mapped to this error code
    pub fn ck_rv_from_error<E>(ckrv: CK_RV, error: E) -> Error
    where
        E: Into<Box<dyn error::Error>> + std::fmt::Display,
    {
        trace_err!(Error {
            kind: ErrorKind::CkError,
            origin: Some(error.into()),
            errmsg: None,
            reqsize: 0,
            ckrv: ckrv,
        })
    }

    /// Creates an error that represents a PKCS#11 Error code, and includes
    /// an error message
    pub fn ck_rv_with_errmsg(ckrv: CK_RV, errmsg: String) -> Error {
        trace_err!(Error {
            kind: ErrorKind::CkError,
            origin: None,
            errmsg: Some(errmsg),
            reqsize: 0,
            ckrv: ckrv,
        })
    }

    /// Creates an AttributeNotFound error, and includes an error message
    pub fn not_found(errmsg: String) -> Error {
        trace_err!(Error {
            kind: ErrorKind::AttributeNotFound,
            origin: None,
            errmsg: Some(errmsg),
            reqsize: 0,
            ckrv: CKR_GENERAL_ERROR,
        })
    }

    /// Creates an general (unspecified) error message from a previous error
    pub fn other_error<E>(error: E) -> Error
    where
        E: Into<Box<dyn error::Error>> + std::fmt::Display,
    {
        trace_err!(Error {
            kind: ErrorKind::Nested,
            origin: Some(error.into()),
            errmsg: None,
            reqsize: 0,
            ckrv: CKR_GENERAL_ERROR,
        })
    }

    /// Creates a BufferTooSmall error and set the required buffer size
    pub fn buf_too_small(reqsize: usize) -> Error {
        trace_err!(Error {
            kind: ErrorKind::BufferTooSmall,
            origin: None,
            errmsg: None,
            reqsize: reqsize,
            ckrv: CKR_BUFFER_TOO_SMALL,
        })
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
    pub fn rv(&self) -> CK_RV {
        self.ckrv
    }

    /// Returns the associated required buffer size
    pub fn reqsize(&self) -> usize {
        self.reqsize
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ret = match self.kind {
            ErrorKind::CkError => write!(f, "Generic CK error"),
            ErrorKind::AttributeNotFound => write!(f, "Attribute not found"),
            ErrorKind::BufferTooSmall => write!(f, "Buffer too small"),
            ErrorKind::Nested => write!(f, "Nested error"),
        };
        if ret.is_err() {
            return ret;
        }

        let ret = write!(f, ", {}", ckrv_to_string(self.ckrv));
        if ret.is_err() {
            return ret;
        }

        match &self.origin {
            Some(e) => {
                let ret = write!(f, " - Error from: {{ {} }}", e);
                if ret.is_err() {
                    return ret;
                }
            }
            None => (),
        }
        match &self.errmsg {
            Some(e) => {
                let ret = write!(f, " - With message: {}", e);
                if ret.is_err() {
                    return ret;
                }
            }
            None => (),
        }
        if self.reqsize != 0 {
            let ret = write!(f, " - With reqsize: {}", self.reqsize);
            if ret.is_err() {
                return ret;
            }
        }
        Ok(())
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

impl From<CK_RV> for Error {
    /// Maps a naked PKCS#11 Error code to an Error
    fn from(error: CK_RV) -> Error {
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

impl From<ossl::Error> for Error {
    /// Maps an openssl error
    fn from(error: ossl::Error) -> Error {
        match error.kind() {
            ossl::ErrorKind::KeyError => Error::ck_rv(CKR_KEY_INDIGESTIBLE),
            ossl::ErrorKind::WrapperError => Error::ck_rv(CKR_GENERAL_ERROR),
            _ => Error::ck_rv(CKR_DEVICE_ERROR),
        }
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
    E: Into<Box<dyn error::Error>> + std::fmt::Display,
{
    Error::ck_rv_from_error(CKR_GENERAL_ERROR, error)
}

/// Helper to return a CKR_DEVICE_ERROR error
#[allow(dead_code)]
pub fn device_error<E>(error: E) -> Error
where
    E: Into<Box<dyn error::Error>> + std::fmt::Display,
{
    Error::ck_rv_from_error(CKR_DEVICE_ERROR, error)
}

/// Helper to return a CKR_ARGUMENTS_BAD error
pub fn arg_bad<E>(error: E) -> Error
where
    E: Into<Box<dyn error::Error>> + std::fmt::Display,
{
    Error::ck_rv_from_error(CKR_ARGUMENTS_BAD, error)
}

/// Helper to map an Error to a PKCS#11 Error code error
macro_rules! map_err {
    ($map:expr, $err:tt) => {{
        use crate::error::Error;
        $map.map_err(|e| Error::ck_rv_from_error($err, e))
    }};
}
pub(crate) use map_err;
