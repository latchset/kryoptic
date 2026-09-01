// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(not(feature = "fips"))]
static TEST_CONTEXT: ::std::sync::LazyLock<crate::OsslContext> =
    ::std::sync::LazyLock::new(|| crate::OsslContext::new_lib_ctx());

#[cfg(not(feature = "fips"))]
pub fn test_ossl_context() -> &'static crate::OsslContext {
    &TEST_CONTEXT
}

#[cfg(all(not(feature = "fips"), feature = "rfc9580"))]
static TEST_LEGACY_CONTEXT: ::std::sync::LazyLock<crate::OsslContext> =
    ::std::sync::LazyLock::new(|| {
        let mut context = crate::OsslContext::new_lib_ctx();
        // Ignore the errors to load legacy provider
        let _ = context.load_legacy_provider();
        context
    });

#[cfg(feature = "rfc9580")]
pub fn test_ossl_legacy_context() -> &'static crate::OsslContext {
    #[cfg(feature = "fips")]
    {
        panic!("The legacy provider is not available in FIPS build")
    }
    #[cfg(not(feature = "fips"))]
    {
        &TEST_LEGACY_CONTEXT
    }
}

#[cfg(not(feature = "fips"))]
mod aes;

#[cfg(not(feature = "fips"))]
mod brainpool;

#[cfg(not(feature = "fips"))]
mod chacha20;

#[cfg(feature = "rfc9580")]
mod dsa;

#[cfg(feature = "rfc9580")]
mod cipher;

#[cfg(feature = "rfc9580")]
mod digest;

#[cfg(all(ossl_v350, not(feature = "fips")))]
mod mldsa;

#[cfg(feature = "dynamic")]
#[test]
fn test_permissive_fips() {
    let mut ctx = crate::OsslContext::new_lib_ctx();
    ctx.load_default_configuration().unwrap();
    if ctx.fips_is_enabled() {
        let res = ctx.set_permissive_fips();
        assert!(res.is_ok());
    }
}

#[cfg(feature = "dynamic")]
#[test]
fn test_provider_version() {
    let mut ctx = crate::OsslContext::new_lib_ctx();
    ctx.load_default_provider().unwrap();
    let prov = unsafe {
        crate::bindings::OSSL_PROVIDER_load(
            ctx.ptr(),
            crate::DEFAULT_PROVIDER_NAME.as_ptr(),
        )
    };
    assert!(!prov.is_null());
    let mut pb = crate::OsslParamBuilder::with_capacity(1);
    pb.add_empty_utf8_ptr(crate::cstr!(
        crate::bindings::OSSL_PROV_PARAM_VERSION
    ))
    .unwrap();
    let mut params = pb.finalize();
    let ret = unsafe {
        crate::bindings::OSSL_PROVIDER_get_params(prov, params.as_mut_ptr())
    };
    unsafe { crate::bindings::OSSL_PROVIDER_unload(prov) };
    assert_eq!(ret, 1);
    let ver = params
        .get_utf8_string(crate::cstr!(crate::bindings::OSSL_PROV_PARAM_VERSION))
        .unwrap();
    assert!(!ver.to_bytes().is_empty());
}

#[cfg(all(ossl_v350, feature = "dynamic"))]
#[test]
fn test_shake_digest_with_broken_shake_context() {
    let mut ctx = crate::OsslContext::new_lib_ctx();
    ctx.load_default_provider().unwrap();
    ctx.broken_shake = true;
    ctx.fips_permissive = true;

    let seed = vec![0x42u8; 32];
    let key = crate::pkey::EvpPkey::import(
        &ctx,
        crate::pkey::EvpPkeyType::Mldsa44,
        crate::pkey::PkeyData::Mlkey(crate::pkey::MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(crate::OsslSecret::from_vec(seed)),
        }),
    );
    assert!(key.is_ok());
}
