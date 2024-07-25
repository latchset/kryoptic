// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::hmac;
use super::object;
use super::tests;
use super::tlskdf;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_tlsprf_vectors() {
    /* tests from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/2/ */

    let vector = [
        (
            /* secret */
            hex::decode("e18828740352b530d69b34c6597dea2e").unwrap(),
            /* label+seed */
            hex::decode("74657374206c6162656cf5a3fe6d34e2e28560fdcaf6823f9091")
                .unwrap(),
            /* output */
            hex::decode(
                "224d8af3c0453393a9779789d21cf7da5ee62ae6b617873d4894\
                 28efc8dd58d1566e7029e2ca3a5ecd355dc64d4d927e2fbd78c4\
                 233e8604b14749a77a92a70fddf614bc0df623d798604e4ca551\
                 2794d802a258e82f86cf",
            )
            .unwrap(),
            /* prf mechtype */
            CKM_SHA224_HMAC,
            /* name */
            "TLS1.2PRF-SHA224",
        ),
        (
            hex::decode("9bbe436ba940f017b17652849a71db35").unwrap(),
            hex::decode("74657374206c6162656ca0ba9f936cda311827a6f796ffd5198c")
                .unwrap(),
            hex::decode(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b\
                 52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7\
                 077def17abfd3797c0564bab4fbc91666e9def9b97fce34f7967\
                 89baa48082d122ee42c5a72e5a5110fff70187347b66",
            )
            .unwrap(),
            CKM_SHA256_HMAC,
            "TLS1.2PRF-SHA256",
        ),
        (
            hex::decode("b0323523c1853599584d88568bbb05eb").unwrap(),
            hex::decode("74657374206c6162656cd4640e12e4bcdbfb437f03e6ae418ee5")
                .unwrap(),
            hex::decode(
                "1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a46\
                 38d7d508b283042df6789875c7147e906d868bc75c45e20eb40c\
                 1cf4a1713b27371f68432592f7dc8ea8ef223e12ea8507841311\
                 bf68653d0cfc4056d811f025c45ddfa6e6fec702f054b409d6f2\
                 8dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9f6b9\
                 826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8\
                 f81ca0a60d1a397a1028bff5d2ef5066126842fb8da4197632bd\
                 b54ff6633f86bbc836e640d4d898",
            )
            .unwrap(),
            CKM_SHA512_HMAC,
            "TLS1.2PRF-SHA512",
        ),
        (
            hex::decode("b80b733d6ceefcdc71566ea48e5567df").unwrap(),
            hex::decode("74657374206c6162656ccd665cf6a8447dd6ff8b27555edb7465")
                .unwrap(),
            hex::decode(
                "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd794\
                 2107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb40\
                 0fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b3\
                 2fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d\
                 31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8\
                 f3a26854308d5eaa3be85e0990703d73e56f",
            )
            .unwrap(),
            CKM_SHA384_HMAC,
            "TLS1.2PRF-SHA384",
        ),
    ];

    for v in vector {
        let secret = &v.0;
        let seed = &v.1;
        let output = &v.2;
        let mechtype = v.3;
        let name = v.4;

        /* mock key */
        let mut key = object::Object::new();
        key.set_attr(attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))
            .unwrap();
        key.set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))
            .unwrap();
        key.set_attr(attribute::from_bytes(CKA_VALUE, secret.clone()))
            .unwrap();
        key.set_attr(attribute::from_ulong(
            CKA_VALUE_LEN,
            secret.len() as CK_ULONG,
        ))
        .unwrap();
        key.set_attr(attribute::from_bool(CKA_DERIVE, true))
            .unwrap();

        let mech = hmac::test_get_hmac(mechtype);

        let out =
            tlskdf::test_tlsprf(&key, &mech, mechtype, seed, output.len())
                .unwrap();
        if &out != output {
            panic!("Failed tls prf vector named {}", name);
        }
    }
}
