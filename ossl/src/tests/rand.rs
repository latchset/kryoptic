// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use serial_test::parallel;

use crate::rand::{get_random, get_random_ex};
use crate::tests::test_ossl_context;
use crate::ErrorKind;
use crate::OsslContext;

#[test]
#[parallel]
fn test_get_random() {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    // Regular random
    get_random(&mut buf1, false).unwrap();
    assert_ne!(buf1, [0u8; 32]);

    get_random(&mut buf2, false).unwrap();
    assert_ne!(buf2, [0u8; 32]);
    assert_ne!(buf1, buf2);

    // Private random
    let mut priv_buf1 = [0u8; 32];
    let mut priv_buf2 = [0u8; 32];

    get_random(&mut priv_buf1, true).unwrap();
    assert_ne!(priv_buf1, [0u8; 32]);

    get_random(&mut priv_buf2, true).unwrap();
    assert_ne!(priv_buf2, [0u8; 32]);
    assert_ne!(priv_buf1, priv_buf2);
    assert_ne!(priv_buf1, buf1);
}

#[test]
#[parallel]
fn test_get_random_sizes() {
    // Empty buffer
    let mut empty = [];
    assert_eq!(
        get_random(&mut empty, false).unwrap_err().kind(),
        ErrorKind::BufferSize
    );
    assert_eq!(
        get_random(&mut empty, true).unwrap_err().kind(),
        ErrorKind::BufferSize
    );

    // Various sizes
    for size in [1, 7, 16, 64, 256, 1024] {
        let mut buf = vec![0u8; size];
        get_random(&mut buf, false).unwrap();
        if size >= 16 {
            assert_ne!(buf, vec![0u8; size]);
        }

        let mut priv_buf = vec![0u8; size];
        get_random(&mut priv_buf, true).unwrap();
        if size >= 16 {
            assert_ne!(priv_buf, vec![0u8; size]);
        }
    }
}

#[test]
#[parallel]
fn test_get_random_ex() {
    let context = test_ossl_context();

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    // Regular random with context
    get_random_ex(context, &mut buf1, false).unwrap();
    assert_ne!(buf1, [0u8; 32]);

    get_random_ex(context, &mut buf2, false).unwrap();
    assert_ne!(buf2, [0u8; 32]);
    assert_ne!(buf1, buf2);

    // Private random with context
    let mut priv_buf1 = [0u8; 32];
    let mut priv_buf2 = [0u8; 32];

    get_random_ex(context, &mut priv_buf1, true).unwrap();
    assert_ne!(priv_buf1, [0u8; 32]);

    get_random_ex(context, &mut priv_buf2, true).unwrap();
    assert_ne!(priv_buf2, [0u8; 32]);
    assert_ne!(priv_buf1, priv_buf2);
    assert_ne!(priv_buf1, buf1);
}

#[test]
#[parallel]
fn test_get_random_ex_custom_context() {
    let mut ctx = OsslContext::new_lib_ctx_checked().unwrap();
    ctx.load_default_provider().unwrap();

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    get_random_ex(&ctx, &mut buf1, false).unwrap();
    assert_ne!(buf1, [0u8; 32]);

    get_random_ex(&ctx, &mut buf2, true).unwrap();
    assert_ne!(buf2, [0u8; 32]);
    assert_ne!(buf1, buf2);
}

#[test]
#[parallel]
fn test_get_random_ex_sizes() {
    let context = test_ossl_context();

    // Empty buffer
    let mut empty = [];
    assert_eq!(
        get_random_ex(context, &mut empty, false)
            .unwrap_err()
            .kind(),
        ErrorKind::BufferSize
    );
    assert_eq!(
        get_random_ex(context, &mut empty, true).unwrap_err().kind(),
        ErrorKind::BufferSize
    );

    // Various sizes
    for size in [1, 7, 16, 64, 256, 1024] {
        let mut buf = vec![0u8; size];
        get_random_ex(context, &mut buf, false).unwrap();
        if size >= 16 {
            assert_ne!(buf, vec![0u8; size]);
        }

        let mut priv_buf = vec![0u8; size];
        get_random_ex(context, &mut priv_buf, true).unwrap();
        if size >= 16 {
            assert_ne!(priv_buf, vec![0u8; size]);
        }
    }
}

#[test]
#[parallel]
fn test_evp_rand_ctx_hmac_drbg() {
    let context = test_ossl_context();
    let mut drbg = crate::rand::EvpRandCtx::new_hmac_drbg(
        context,
        crate::digest::DigestAlg::Sha2_256,
        b"personalization string",
    )
    .unwrap();

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];

    drbg.generate(&[], &mut out1).unwrap();
    assert_ne!(out1, [0u8; 32]);

    drbg.generate(&[], &mut out2).unwrap();
    assert_ne!(out2, [0u8; 32]);
    assert_ne!(out1, out2);

    let entropy = [0x42u8; 32];
    drbg.reseed(&entropy, &[]).unwrap();

    let mut out3 = [0u8; 32];
    drbg.generate(&[], &mut out3).unwrap();
    assert_ne!(out3, [0u8; 32]);
    assert_ne!(out2, out3);
}
