// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

pub mod executor;
pub mod pkcs11_wrapper;
pub mod profile;
pub mod token_init;

use clap::{Parser, ValueEnum};
use std::fmt;

#[derive(Clone, Debug, ValueEnum)]
pub enum Profile {
    #[value(name = "baseline")]
    Baseline,
    #[value(name = "extended")]
    Extended,
    #[value(name = "authentication")]
    Authentication,
    #[value(name = "complete")]
    Complete,
    #[value(name = "public_certs")]
    PublicCerts,
    #[value(name = "hkdf_tls")]
    HkdfTls,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(short = 'd', long)]
    pub debug: bool,

    #[arg(long)]
    pub init: bool,

    #[arg(short = 'o', long)]
    pub output: Option<String>,

    #[arg(short = 'm', long)]
    pub pkcs11_module: Option<String>,

    #[arg(short = 'i', long)]
    pub pkcs11_initargs: Option<String>,

    #[arg(short = 'p', long)]
    pub pkcs11_pin: Option<String>,

    #[arg(long)]
    pub so_pin: Option<String>,

    #[arg(long)]
    pub token_label: Option<String>,

    #[arg(short = 's', long)]
    pub pkcs11_slot: Option<u64>,

    #[arg(long)]
    pub genkey: Option<String>,

    #[arg(long)]
    pub profile: Option<Profile>,

    pub xml_profile: Option<String>,
}

#[derive(Debug)]
pub struct Error {
    pub msg: String,
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        Error { msg: msg }
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Error {
        Error::from(msg.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Error {}
