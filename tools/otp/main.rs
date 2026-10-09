// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod p11;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use data_encoding::BASE32_NOPAD;
use kryoptic_lib::pkcs11;

use p11::FuncList;

macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        pkcs11::CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as *const _ as pkcs11::CK_VOID_PTR,
            ulValueLen: $length as pkcs11::CK_ULONG,
        }
    };
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum OtpType {
    #[value(name = "totp", alias = "TOTP")]
    Totp,
    #[value(name = "hotp", alias = "HOTP")]
    Hotp,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum SecurityLevel {
    #[value(name = "normal", alias = "NORMAL")]
    Normal,
    #[value(name = "high", alias = "HIGH")]
    High,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum OutputFormat {
    #[value(name = "all", alias = "ALL")]
    All,
    #[value(name = "base32", alias = "BASE32")]
    Base32,
    #[value(name = "hex", alias = "HEX")]
    Hex,
    #[value(name = "uri", alias = "URI")]
    Uri,
}

#[derive(Parser, Debug)]
#[command(
    name = "kryoptic_otp",
    about = "Kryoptic OTP Token Management and Code Generation Tool"
)]
struct Arguments {
    /// Path to Kryoptic PKCS#11 shared library (libkryoptic_pkcs11.so)
    #[arg(short = 'm', long)]
    module: Option<String>,

    /// Path to Kryoptic database file (defaults to ~/.kryoptic_otp/token.sql)
    #[arg(short = 'd', long = "db-path")]
    db_path: Option<String>,

    /// Creates a new OTP instance (requires --otp-name)
    #[arg(short = 'N', long = "new-otp")]
    new_otp: bool,

    /// Name of the OTP instance
    #[arg(short = 'n', long = "otp-name")]
    otp_name: Option<String>,

    /// OTP type: TOTP (default) or HOTP
    #[arg(short = 't', long = "otp-type", value_enum, default_value_t = OtpType::Totp)]
    otp_type: OtpType,

    /// User/SO PIN [prompted if not provided]
    #[arg(short = 'p', long)]
    pin: Option<String>,

    /// Create token without a PIN (sets PIN to "NOPIN")
    #[arg(long = "no-pin", conflicts_with = "pin", requires = "new_otp")]
    no_pin: bool,

    /// Security level: NORMAL (SHA-256, default) or HIGH (SHA-512)
    #[arg(short = 's', long = "security-level", value_enum, default_value_t = SecurityLevel::Normal)]
    security_level: SecurityLevel,

    /// OTP code length: 6, 7, 8 [default: 6]
    #[arg(long, default_value_t = 6)]
    digits: u32,

    /// Time step period in seconds (TOTP only) [default: 30]
    #[arg(long, default_value_t = 30)]
    period: u32,

    /// Issuer string for otpauth URI (e.g. "MyOrg")
    #[arg(long)]
    issuer: Option<String>,

    /// Account identifier for otpauth URI (defaults to otp-name)
    #[arg(long)]
    account: Option<String>,

    /// Output format: all, base32, hex, uri [default: all]
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::All)]
    format: OutputFormat,
}

fn find_module(explicit_path: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit_path {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("Specified PKCS#11 module not found: {}", path));
    }

    if let Ok(dir) = std::env::var("KRYOPTIC") {
        let d = PathBuf::from(dir);
        let candidates = [
            d.join("target/debug/libkryoptic_pkcs11.so"),
            d.join("target/release/libkryoptic_pkcs11.so"),
            d.join("libkryoptic_pkcs11.so"),
            d.join("target/debug/libkryoptic.so"),
            d.join("target/release/libkryoptic.so"),
            d.join("libkryoptic.so"),
        ];
        for c in candidates {
            if c.exists() {
                return Ok(c);
            }
        }
    }

    let local_candidates = [
        PathBuf::from("target/debug/libkryoptic_pkcs11.so"),
        PathBuf::from("target/release/libkryoptic_pkcs11.so"),
        PathBuf::from("../target/debug/libkryoptic_pkcs11.so"),
        PathBuf::from("../target/release/libkryoptic_pkcs11.so"),
    ];
    for c in local_candidates {
        if c.exists() {
            return Ok(c);
        }
    }

    let sys_candidates = [
        PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/pkcs11/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/lib/pkcs11/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/local/lib/pkcs11/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/lib64/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/lib/libkryoptic_pkcs11.so"),
        PathBuf::from("/usr/local/lib/libkryoptic_pkcs11.so"),
    ];
    for c in sys_candidates {
        if c.exists() {
            return Ok(c);
        }
    }

    Ok(PathBuf::from("libkryoptic_pkcs11.so"))
}

fn resolve_db_path(explicit_path: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit_path {
        return Ok(PathBuf::from(path));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".kryoptic_otp/token.sql"));
    }
    Ok(PathBuf::from(".kryoptic_otp/token.sql"))
}

fn prompt_pin() -> Result<String, String> {
    eprint!("Enter PIN: ");
    std::io::stderr().flush().map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let is_tty = unsafe { libc::isatty(fd) } != 0;
        if is_tty {
            let mut termios: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 {
                let mut no_echo = termios;
                no_echo.c_lflag &= !libc::ECHO;
                unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) };
                let mut input = String::new();
                let res = std::io::stdin().read_line(&mut input);
                unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
                eprintln!();
                res.map_err(|e| e.to_string())?;
                return Ok(input
                    .trim_end_matches(&['\r', '\n'][..])
                    .to_string());
            }
        }
    }

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(input.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn get_pin(explicit_pin: Option<&str>) -> Result<String, String> {
    if let Some(pin) = explicit_pin {
        return Ok(pin.to_string());
    }
    if let Ok(pin) = std::env::var("KRYOPTIC_OTP_PIN") {
        return Ok(pin);
    }
    if let Ok(pin) = std::env::var("PIN") {
        return Ok(pin);
    }
    prompt_pin()
}

fn login_user(
    fns: &FuncList,
    session: pkcs11::CK_SESSION_HANDLE,
    explicit_pin: Option<&str>,
) -> Result<(), String> {
    if let Some(pin) = explicit_pin {
        return fns.login(session, pkcs11::CKU_USER, pin);
    }
    if let Ok(pin) = std::env::var("KRYOPTIC_OTP_PIN") {
        return fns.login(session, pkcs11::CKU_USER, &pin);
    }
    if let Ok(pin) = std::env::var("PIN") {
        return fns.login(session, pkcs11::CKU_USER, &pin);
    }
    if fns.try_login(session, pkcs11::CKU_USER, "NOPIN").is_ok() {
        return Ok(());
    }
    let pin = prompt_pin()?;
    fns.login(session, pkcs11::CKU_USER, &pin)
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::new();
    for b in input.bytes() {
        match b {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}

fn generate_otpauth_uri(
    otp_type: OtpType,
    secret_base32: &str,
    account: &str,
    issuer: Option<&str>,
    algorithm: &str,
    digits: u32,
    period: u32,
) -> String {
    let type_str = match otp_type {
        OtpType::Totp => "totp",
        OtpType::Hotp => "hotp",
    };
    let label = match issuer {
        Some(iss) => format!("{}:{}", url_encode(iss), url_encode(account)),
        None => url_encode(account),
    };
    let mut params = vec![
        format!("secret={}", secret_base32),
        format!("algorithm={}", algorithm),
        format!("digits={}", digits),
    ];
    if let Some(iss) = issuer {
        params.push(format!("issuer={}", url_encode(iss)));
    }
    match otp_type {
        OtpType::Totp => {
            params.push(format!("period={}", period));
        }
        OtpType::Hotp => {
            params.push("counter=0".to_string());
        }
    }
    format!("otpauth://{}/{}?{}", type_str, label, params.join("&"))
}

fn get_key_label(
    fns: &FuncList,
    session: pkcs11::CK_SESSION_HANDLE,
    handle: pkcs11::CK_OBJECT_HANDLE,
) -> Result<String, String> {
    let bytes = fns.get_attribute_bytes(session, handle, pkcs11::CKA_LABEL)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn matches_key_name(label: &str, name: &str) -> bool {
    if label == name {
        return true;
    }
    if let Some((_type, sub_name)) = label.split_once(':') {
        if sub_name == name {
            return true;
        }
    }
    false
}

fn run_new_otp(
    fns: &FuncList,
    db_path: &Path,
    args: &Arguments,
) -> Result<(), String> {
    let otp_name = args
        .otp_name
        .as_deref()
        .ok_or("--otp-name is required when creating a new OTP (-N)")?;

    if args.digits < 6 || args.digits > 8 {
        return Err(format!(
            "Invalid OTP digits '{}'. Must be 6, 7, or 8.",
            args.digits
        ));
    }
    if args.period == 0 {
        return Err("Period must be greater than 0.".into());
    }

    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create directory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }
    }

    fns.initialize(db_path)?;

    let slots = fns.get_slot_list()?;
    if slots.is_empty() {
        return Err("No PKCS#11 slots available for database".into());
    }
    let slot = slots[0];

    let token_info = fns.get_token_info(slot)?;
    let is_initialized =
        (token_info.flags & pkcs11::CKF_TOKEN_INITIALIZED) != 0;

    let session = if !is_initialized {
        let pin = if args.no_pin {
            "NOPIN".to_string()
        } else {
            get_pin(args.pin.as_deref())?
        };
        fns.init_token(slot, &pin, "Kryoptic OTP Token")?;
        let so_session = fns.open_rw_session(slot)?;
        fns.login(so_session, pkcs11::CKU_SO, &pin)?;
        fns.init_pin(so_session, &pin)?;
        fns.logout(so_session)?;
        fns.close_session(so_session)?;
        let sess = fns.open_rw_session(slot)?;
        fns.login(sess, pkcs11::CKU_USER, &pin)?;
        sess
    } else {
        if args.no_pin {
            return Err(
                "--no-pin can only be used when creating the first token (token is already initialized)"
                    .into(),
            );
        }
        let sess = fns.open_rw_session(slot)?;
        login_user(fns, sess, args.pin.as_deref())?;
        sess
    };

    // Check for duplicate key label
    let mut class_val = pkcs11::CKO_OTP_KEY;
    let search_template = [make_attribute!(
        pkcs11::CKA_CLASS,
        &mut class_val,
        std::mem::size_of::<pkcs11::CK_ULONG>()
    )];
    let existing_handles = fns.find_objects(session, &search_template)?;
    for &h in &existing_handles {
        let label = get_key_label(fns, session, h)?;
        if matches_key_name(&label, otp_name) {
            let _ = fns.logout(session);
            let _ = fns.close_session(session);
            return Err(format!(
                "An OTP key matching '{}' already exists on the token.",
                otp_name
            ));
        }
    }

    let (seed_len, algo_name) = match args.security_level {
        SecurityLevel::Normal => (32, "SHA256"),
        SecurityLevel::High => (64, "SHA512"),
    };

    let mut seed = fns.generate_random(session, seed_len)?;

    let type_prefix = match args.otp_type {
        OtpType::Totp => "totp",
        OtpType::Hotp => "hotp",
    };
    let key_label = format!("{}:{}", type_prefix, otp_name);

    let mut key_type_val = pkcs11::CKK_HOTP;
    let mut true_val: pkcs11::CK_BBOOL = pkcs11::CK_TRUE;
    let mut false_val: pkcs11::CK_BBOOL = pkcs11::CK_FALSE;
    let mut digits_val = args.digits as pkcs11::CK_ULONG;
    let mut format_val = pkcs11::CK_OTP_FORMAT_DECIMAL;
    let mut counter_req_val = pkcs11::CK_OTP_PARAM_OPTIONAL;
    let initial_counter = [0u8; 8];

    let create_template = [
        make_attribute!(
            pkcs11::CKA_CLASS,
            &mut class_val,
            std::mem::size_of::<pkcs11::CK_ULONG>()
        ),
        make_attribute!(
            pkcs11::CKA_KEY_TYPE,
            &mut key_type_val,
            std::mem::size_of::<pkcs11::CK_ULONG>()
        ),
        make_attribute!(
            pkcs11::CKA_TOKEN,
            &mut true_val,
            std::mem::size_of::<pkcs11::CK_BBOOL>()
        ),
        make_attribute!(pkcs11::CKA_LABEL, key_label.as_ptr(), key_label.len()),
        make_attribute!(pkcs11::CKA_VALUE, seed.as_ptr(), seed.len()),
        make_attribute!(
            pkcs11::CKA_SIGN,
            &mut true_val,
            std::mem::size_of::<pkcs11::CK_BBOOL>()
        ),
        make_attribute!(
            pkcs11::CKA_VERIFY,
            &mut true_val,
            std::mem::size_of::<pkcs11::CK_BBOOL>()
        ),
        make_attribute!(
            pkcs11::CKA_OTP_LENGTH,
            &mut digits_val,
            std::mem::size_of::<pkcs11::CK_ULONG>()
        ),
        make_attribute!(
            pkcs11::CKA_OTP_FORMAT,
            &mut format_val,
            std::mem::size_of::<pkcs11::CK_ULONG>()
        ),
        make_attribute!(
            pkcs11::CKA_OTP_COUNTER_REQUIREMENT,
            &mut counter_req_val,
            std::mem::size_of::<pkcs11::CK_ULONG>()
        ),
        make_attribute!(
            pkcs11::CKA_OTP_COUNTER,
            initial_counter.as_ptr(),
            initial_counter.len()
        ),
        make_attribute!(
            pkcs11::CKA_SENSITIVE,
            &mut true_val,
            std::mem::size_of::<pkcs11::CK_BBOOL>()
        ),
        make_attribute!(
            pkcs11::CKA_EXTRACTABLE,
            &mut false_val,
            std::mem::size_of::<pkcs11::CK_BBOOL>()
        ),
    ];

    fns.create_object(session, &create_template)?;

    let _ = fns.logout(session);
    let _ = fns.close_session(session);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            db_path,
            std::fs::Permissions::from_mode(0o600),
        );
    }

    let base32_secret = BASE32_NOPAD.encode(&seed);
    let hex_secret = hex::encode(&seed);
    let account = args.account.as_deref().unwrap_or(otp_name);
    let uri = generate_otpauth_uri(
        args.otp_type,
        &base32_secret,
        account,
        args.issuer.as_deref(),
        algo_name,
        args.digits,
        args.period,
    );

    // Securely clear raw seed from memory
    seed.fill(0);

    match args.format {
        OutputFormat::Base32 => println!("{}", base32_secret),
        OutputFormat::Hex => println!("{}", hex_secret),
        OutputFormat::Uri => println!("{}", uri),
        OutputFormat::All => {
            println!("OTP Name:       {}", otp_name);
            println!(
                "Type:           {}",
                match args.otp_type {
                    OtpType::Totp => "TOTP",
                    OtpType::Hotp => "HOTP",
                }
            );
            println!("Algorithm:      {}", algo_name);
            println!("Digits:         {}", args.digits);
            if args.otp_type == OtpType::Totp {
                println!("Period:         {}s", args.period);
            }
            if let Some(iss) = &args.issuer {
                println!("Issuer:         {}", iss);
            }
            println!("Account:        {}", account);
            println!("Base32 Secret:  {}", base32_secret);
            println!("Hex Secret:     {}", hex_secret);
            println!("URI:            {}", uri);
        }
    }

    Ok(())
}

fn run_generate_code(
    fns: &FuncList,
    db_path: &Path,
    args: &Arguments,
) -> Result<(), String> {
    if !db_path.exists() {
        return Err(format!(
            "Database file '{}' does not exist. Use -N to create a new OTP.",
            db_path.display()
        ));
    }

    fns.initialize(db_path)?;

    let slots = fns.get_slot_list()?;
    if slots.is_empty() {
        return Err("No PKCS#11 slots available for database".into());
    }
    let slot = slots[0];

    let session = fns.open_rw_session(slot)?;
    login_user(fns, session, args.pin.as_deref())?;

    let mut class_val = pkcs11::CKO_OTP_KEY;
    let search_template = [make_attribute!(
        pkcs11::CKA_CLASS,
        &mut class_val,
        std::mem::size_of::<pkcs11::CK_ULONG>()
    )];
    let handles = fns.find_objects(session, &search_template)?;

    if handles.is_empty() {
        let _ = fns.logout(session);
        let _ = fns.close_session(session);
        return Err(
            "No OTP keys found in database. Use -N to create a new OTP.".into(),
        );
    }

    let target_handle = if handles.len() == 1 {
        if let Some(req_name) = &args.otp_name {
            let label = get_key_label(fns, session, handles[0])?;
            if !matches_key_name(&label, req_name) {
                let _ = fns.logout(session);
                let _ = fns.close_session(session);
                return Err(format!(
                    "The single OTP key on token is '{}', which does not match requested '{}'",
                    label, req_name
                ));
            }
        }
        handles[0]
    } else {
        let req_name = match &args.otp_name {
            Some(n) => n,
            None => {
                let mut names = Vec::new();
                for &h in &handles {
                    if let Ok(label) = get_key_label(fns, session, h) {
                        names.push(label);
                    }
                }
                let _ = fns.logout(session);
                let _ = fns.close_session(session);
                return Err(format!(
                    "Multiple OTP keys found ({:?}). Please specify which one to use with -n/--otp-name.",
                    names
                ));
            }
        };

        let mut matched = Vec::new();
        for &h in &handles {
            let label = get_key_label(fns, session, h)?;
            if matches_key_name(&label, req_name) {
                matched.push(h);
            }
        }

        match matched.len() {
            0 => {
                let _ = fns.logout(session);
                let _ = fns.close_session(session);
                return Err(format!(
                    "No OTP key matching '{}' found.",
                    req_name
                ));
            }
            1 => matched[0],
            _ => {
                let _ = fns.logout(session);
                let _ = fns.close_session(session);
                return Err(format!("Multiple OTP keys match '{}'.", req_name));
            }
        }
    };

    let label = get_key_label(fns, session, target_handle)?;
    let key_otp_type = if label.starts_with("hotp:") {
        OtpType::Hotp
    } else if label.starts_with("totp:") {
        OtpType::Totp
    } else {
        args.otp_type
    };

    let counter = match key_otp_type {
        OtpType::Totp => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("System clock error: {}", e))?
                .as_secs();
            let step = if args.period > 0 { args.period } else { 30 };
            Some(now / (step as u64))
        }
        OtpType::Hotp => None,
    };

    let code = fns.sign_otp(session, target_handle, counter)?;

    let _ = fns.logout(session);
    let _ = fns.close_session(session);

    println!("{}", code);

    Ok(())
}

fn main() -> ExitCode {
    let args = Arguments::parse();

    let module_path = match find_module(args.module.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };

    let db_path = match resolve_db_path(args.db_path.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };

    let fns = match FuncList::load(&module_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };

    let res = if args.new_otp {
        run_new_otp(&fns, &db_path, &args)
    } else {
        run_generate_code(&fns, &db_path, &args)
    };

    let _ = fns.finalize();

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("foo bar"), "foo%20bar");
        assert_eq!(url_encode("user@example.com"), "user%40example.com");
        assert_eq!(url_encode("My Org:Corp"), "My%20Org%3ACorp");
    }

    #[test]
    fn test_generate_otpauth_uri_totp() {
        let uri = generate_otpauth_uri(
            OtpType::Totp,
            "JBSWY3DPEHPK3PXP",
            "alice@example.com",
            Some("Acme Inc"),
            "SHA256",
            6,
            30,
        );
        assert_eq!(
            uri,
            "otpauth://totp/Acme%20Inc:alice%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&issuer=Acme%20Inc&period=30"
        );
    }

    #[test]
    fn test_generate_otpauth_uri_hotp() {
        let uri = generate_otpauth_uri(
            OtpType::Hotp,
            "JBSWY3DPEHPK3PXP",
            "bob",
            None,
            "SHA512",
            8,
            30,
        );
        assert_eq!(
            uri,
            "otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&counter=0"
        );
    }

    #[test]
    fn test_matches_key_name() {
        assert!(matches_key_name("test_totp", "test_totp"));
        assert!(matches_key_name("totp:test_totp", "test_totp"));
        assert!(matches_key_name("hotp:mykey", "mykey"));
        assert!(matches_key_name("totp:foo:bar", "foo:bar"));
        assert!(!matches_key_name("totp:test_totp", "other"));
    }

    #[test]
    fn test_cli_parsing() {
        let args = Arguments::try_parse_from([
            "kryoptic_otp",
            "-N",
            "-n",
            "token1",
            "--digits",
            "8",
            "-s",
            "high",
            "-f",
            "base32",
        ])
        .unwrap();
        assert!(args.new_otp);
        assert_eq!(args.otp_name.as_deref(), Some("token1"));
        assert_eq!(args.digits, 8);
        assert_eq!(args.security_level, SecurityLevel::High);
        assert_eq!(args.format, OutputFormat::Base32);
        assert_eq!(args.otp_type, OtpType::Totp);
        assert_eq!(args.period, 30);
    }

    #[test]
    fn test_cli_parsing_no_pin() {
        let args = Arguments::try_parse_from([
            "kryoptic_otp",
            "-N",
            "-n",
            "token_nopin",
            "--no-pin",
        ])
        .unwrap();
        assert!(args.new_otp);
        assert!(args.no_pin);
        assert!(args.pin.is_none());

        assert!(Arguments::try_parse_from([
            "kryoptic_otp",
            "-N",
            "-n",
            "token_nopin",
            "--no-pin",
            "-p",
            "1234",
        ])
        .is_err());
        assert!(Arguments::try_parse_from([
            "kryoptic_otp",
            "-n",
            "token_nopin",
            "--no-pin"
        ])
        .is_err());
    }
}
