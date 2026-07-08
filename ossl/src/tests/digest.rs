// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::digest::{DigestAlg, OsslDigest};
use crate::tests::test_ossl_context;

#[test]
#[parallel]
fn test_md5() {
    // the test vectors from wikipedia
    // https://en.wikipedia.org/wiki/MD5#MD5_hashes
    let expect_digest =
        hex::decode("9e107d9d372bb6826bd81d3542a419d6").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::Md5, None).unwrap();
    ctx.update(b"The quick brown fox jumps over the lazy dog")
        .unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);

    let expect_digest =
        hex::decode("e4d909c290d0fb1ca068ffaddf22cbd0").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::Md5, None).unwrap();
    ctx.update(b"The quick brown fox jumps over the lazy dog.")
        .unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);

    let expect_digest =
        hex::decode("d41d8cd98f00b204e9800998ecf8427e").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::Md5, None).unwrap();
    ctx.update(b"").unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);
}

#[test]
#[parallel]
fn test_ripemd160() {
    // the test vectors from wikipedia
    // https://en.wikipedia.org/wiki/RIPEMD#RIPEMD-160_hashes
    let expect_digest =
        hex::decode("37f332f68db77bd9d7edd4969571ad671cf9dd3b").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::RipeMd160, None)
            .unwrap();
    ctx.update(b"The quick brown fox jumps over the lazy dog")
        .unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);

    let expect_digest =
        hex::decode("132072df690933835eb8b6ad0b77e7b6f14acad7").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::RipeMd160, None)
            .unwrap();
    ctx.update(b"The quick brown fox jumps over the lazy cog")
        .unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);

    let expect_digest =
        hex::decode("9c1185a5c5e9fc54612808977ee8f548b2258d31").unwrap();
    let mut ctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::RipeMd160, None)
            .unwrap();
    ctx.update(b"").unwrap();
    let mut digest = vec![0u8; ctx.size()];
    ctx.finalize(&mut digest).unwrap();
    assert_eq!(digest, expect_digest);
}
