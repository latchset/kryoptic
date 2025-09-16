// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(not(feature = "fips"))]
static TEST_CONTEXT: ::std::sync::LazyLock<crate::OsslContext> =
    ::std::sync::LazyLock::new(|| crate::OsslContext::new_lib_ctx());

pub fn test_ossl_context() -> &'static crate::OsslContext {
    #[cfg(feature = "fips")]
    {
        crate::fips::get_libctx()
    }
    #[cfg(not(feature = "fips"))]
    {
        &TEST_CONTEXT
    }
}

#[cfg(not(feature = "fips"))]
mod brainpool;

#[cfg(feature = "rfc9580")]
mod dsa;

#[cfg(feature = "rfc9580")]
mod tripledes;
