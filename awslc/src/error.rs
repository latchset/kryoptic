// Error type for the `awslc` crate, mirroring the shape of `ossl::Error`
// so `src/error.rs` can convert both the same way.

use crate::ffi;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorKind {
    /// AWS-LC returned a NULL pointer where a valid one was expected.
    NullPtr,
    /// An AWS-LC C function returned a failure status code.
    BackendError,
    /// A caller-provided buffer was too small.
    BufferSize,
    /// An error internal to this crate's Rust-level logic (not AWS-LC's).
    WrapperError,
    /// A cryptographic verification (e.g. an AEAD tag check) failed.
    VerifyFailed,
    /// A key-agreement/derive operation rejected its input (e.g. X25519's
    /// small-order/all-zero shared-secret rejection). Distinct from
    /// `VerifyFailed`: this is not a signature/tag check, and PKCS#11
    /// requires a different `CK_RV` for `C_DeriveKey` failures than for
    /// `C_Verify*` failures.
    AgreementFailed,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Constructs an `Error` and clears AWS-LC's per-thread error queue
    /// (`ERR_clear_error`). Every fallible operation in this crate
    /// constructs its `Error` through here (directly or via `?`), making
    /// this the one choke point to clear the queue from, rather than
    /// sprinkling `ERR_clear_error()` calls through every individual FFI
    /// call site. Without this, a failure leaves its pushed error(s) in
    /// the calling thread's queue indefinitely: in a host process that
    /// also links OpenSSL/AWS-LC directly on the same thread (a realistic
    /// scenario for a PKCS#11 module), that can pollute the host's own
    /// `ERR_get_error()` diagnostics, and in general the queue would
    /// otherwise grow unbounded for the life of the thread.
    pub fn new(kind: ErrorKind) -> Error {
        unsafe { ffi::ERR_clear_error() };
        Error { kind }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "awslc backend error: {:?}", self.kind)
    }
}

impl std::error::Error for Error {}
