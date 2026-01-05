use std::process::ExitCode;

use clap::Parser;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(short = 'm', long)]
    pkcs11_module: String,

    #[arg(short = 'p', long)]
    pin: String,
}

fn main() -> ExitCode {
    let args = Arguments::parse();

    let pkcs11 = Pkcs11::new(args.pkcs11_module).unwrap();

    // initialize the library
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();

    // find a slot, get the first one
    let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

    // open a session
    let session = pkcs11.open_rw_session(slot).unwrap();
    // log in the session
    let pin = AuthPin::new(args.pin.into());
    session.login(UserType::User, Some(&pin)).unwrap();

    // Find the certificate with testCert label
    let id = vec![0x00, 0x01];
    let template = vec![
        Attribute::Token(true),
        Attribute::Id(id.clone()),
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Label("testCert".into()),
    ];

    let found_keys = session.find_objects(&template).unwrap();
    if found_keys.len() != 1 {
        eprintln!(
            "Failed to find the test certificate. Found {} objects.",
            found_keys.len()
        );
        return ExitCode::from(0xFF);
    }

    // find the private key and make a signature
    let mut template = vec![
        Attribute::Token(true),
        Attribute::Id(id),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
    ];
    let priv_handle = session.find_objects(&template).unwrap().remove(0);

    let data = "Signature Test";
    let signature = session
        .sign(&Mechanism::RsaPkcs, priv_handle, data.as_bytes())
        .unwrap();

    template[2] = Attribute::Class(ObjectClass::PUBLIC_KEY);
    let pub_handle = session.find_objects(&template).unwrap().remove(0);
    session
        .verify(&Mechanism::RsaPkcs, pub_handle, data.as_bytes(), &signature)
        .unwrap();

    ExitCode::from(0)
}
