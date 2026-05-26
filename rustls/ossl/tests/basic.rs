use rustls::{ClientConfig, ClientConnection};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

mod common;

fn run_openssl_server_basic(
    key_args: &[&str],
    version: &'static rustls::SupportedProtocolVersion,
    cipher_filter: &str,
) {
    let dir = std::env::temp_dir().join(format!(
        "rustls_ossl_test_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let key_path = dir.join("key.pem");
    let cert_path = dir.join("cert.pem");

    // Generate a file to be served to the client
    let test_file_path = dir.join("test.txt");
    let test_content = b"OpenSSL -WWW test file content";
    std::fs::write(&test_file_path, test_content).unwrap();

    // Generate self-signed certificate
    let mut args = vec!["req", "-x509"];
    args.extend_from_slice(key_args);
    args.extend_from_slice(&[
        "-keyout",
        key_path.to_str().unwrap(),
        "-out",
        cert_path.to_str().unwrap(),
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]);

    let status = Command::new("openssl")
        .args(&args)
        .status()
        .expect("failed to run openssl req");
    assert!(status.success());

    // Pick a dynamic available port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Start OpenSSL server
    let mut server = Command::new("openssl")
        .current_dir(&dir)
        .args(&[
            "s_server",
            "-key",
            key_path.to_str().unwrap(),
            "-cert",
            cert_path.to_str().unwrap(),
            "-accept",
            &port.to_string(),
            "-WWW",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run openssl s_server");

    // Wait for the server to be ready
    let mut connected = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(connected, "openssl s_server did not start");

    // Load certificate for pinning
    let cert_file = std::fs::File::open(&cert_path).unwrap();
    let mut reader = std::io::BufReader::new(cert_file);
    let cert = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();

    // Use the rustls ossl module as CryptoProvider
    let mut provider = rustls_ossl::default_provider();
    provider
        .cipher_suites
        .retain(|cs| format!("{:?}", cs.suite()).contains(cipher_filter));
    assert!(
        !provider.cipher_suites.is_empty(),
        "No cipher suites matched filter"
    );
    let provider = Arc::new(provider);
    let verifier = common::PinnedSelfSignedVerifier::new(cert.into_owned());

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let rc_config = Arc::new(config);
    let server_name = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(rc_config, server_name).unwrap();

    // Connect and verify using rustls
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = rustls::Stream::new(&mut client, &mut socket);

    stream.write_all(b"GET /test.txt HTTP/1.0\r\n\r\n").unwrap();
    let mut plaintext = Vec::new();
    stream.read_to_end(&mut plaintext).unwrap();

    let header_end = plaintext
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("Response does not contain HTTP headers");

    let body = &plaintext[header_end + 4..];
    assert_eq!(
        body, test_content,
        "Downloaded content does not match original"
    );

    // Ensure we can properly kill the process and clean up
    server.kill().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

macro_rules! test_openssl_server_basic {
    ($name:ident, $args:expr) => {
        mod $name {
            use super::*;

            #[cfg(feature = "tls12")]
            #[test]
            fn tls12_aes128() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS12,
                    "AES_128",
                );
            }

            #[cfg(feature = "tls12")]
            #[test]
            fn tls12_aes256() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS12,
                    "AES_256",
                );
            }

            #[cfg(feature = "tls12")]
            #[test]
            fn tls12_chacha20() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS12,
                    "CHACHA20",
                );
            }

            #[test]
            fn tls13_aes128() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS13,
                    "AES_128",
                );
            }

            #[test]
            fn tls13_aes256() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS13,
                    "AES_256",
                );
            }

            #[test]
            fn tls13_chacha20() {
                run_openssl_server_basic(
                    $args,
                    &rustls::version::TLS13,
                    "CHACHA20",
                );
            }
        }
    };
}

test_openssl_server_basic!(
    test_openssl_server_basic_rsa,
    &["-newkey", "rsa:2048"]
);
test_openssl_server_basic!(
    test_openssl_server_basic_ecdsa_p256,
    &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
);
test_openssl_server_basic!(
    test_openssl_server_basic_ecdsa_p384,
    &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1"]
);
test_openssl_server_basic!(
    test_openssl_server_basic_ecdsa_p521,
    &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp521r1"]
);
test_openssl_server_basic!(
    test_openssl_server_basic_ed25519,
    &["-newkey", "ed25519"]
);
test_openssl_server_basic!(
    test_openssl_server_basic_ed448,
    &["-newkey", "ed448"]
);
