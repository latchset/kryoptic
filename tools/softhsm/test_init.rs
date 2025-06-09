use std::process::ExitCode;

use clap::Parser;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(short = 'm', long)]
    pkcs11_module: String,

    #[arg(short = 'p', long)]
    pin: String,

    #[arg(short = 's', long)]
    so_pin: String,

    #[arg(short = 'l', long)]
    token_label: String,
}

fn main() -> ExitCode {
    let args = Arguments::parse();

    let pkcs11 = Pkcs11::new(args.pkcs11_module).unwrap();

    // initialize the library
    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    // find a slot, get the first one
    let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

    let so_pin = AuthPin::new(args.so_pin.into());
    pkcs11.init_token(slot, &so_pin, &args.token_label).unwrap();

    // open a SO session
    let session = pkcs11.open_rw_session(slot).unwrap();
    // log in the session
    session.login(UserType::So, Some(&so_pin)).unwrap();

    // Initialize the User Pin
    let pin = AuthPin::new(args.pin.into());
    session.init_pin(&pin).unwrap();

    ExitCode::from(0)
}
