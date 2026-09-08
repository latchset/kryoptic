// Regression test for https://github.com/latchset/kryoptic/issues/490:
// C_Verify on a tampered signature must return CKR_SIGNATURE_INVALID, not CKR_DEVICE_ERROR.
mod rc_common;

#[test]
#[cfg(feature = "integration_tests")]
fn verify_of_tampered_data_returns_signature_invalid(
) -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::error::{Error as CkError, RvError};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    let (pkcs11, slot) = rc_common::setup_token("bug490_repro", &[]);
    let user_pin = AuthPin::new("12345678".into());
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&user_pin))?;

    let pub_tpl = vec![
        Attribute::Verify(true),
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];
    let priv_tpl = vec![Attribute::Sensitive(true), Attribute::Sign(true)];
    let (public, private) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_tpl,
        &priv_tpl,
    )?;

    let data = b"hello pkcs11";
    let signature = session.sign(&Mechanism::Sha256RsaPkcs, private, data)?;

    // Correct data must still verify (guards against a fix that just always returns invalid).
    session.verify(&Mechanism::Sha256RsaPkcs, public, data, &signature)?;

    let mut tampered = data.to_vec();
    tampered[0] ^= 0xFF;

    match session.verify(
        &Mechanism::Sha256RsaPkcs,
        public,
        &tampered,
        &signature,
    ) {
        Err(CkError::Pkcs11(RvError::SignatureInvalid, _)) => Ok(()),
        other => panic!("expected CKR_SIGNATURE_INVALID, got: {other:?}"),
    }
}
