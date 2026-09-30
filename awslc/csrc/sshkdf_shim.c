// Copyright 2026
// See LICENSE.txt file for terms
//
// Neither aws-lc-sys nor aws-lc-fips-sys expose SSHKDF() in their
// generated Rust bindings: both crates hand bindgen a fixed,
// vendored `rust_wrapper.h` that never #includes <openssl/sshkdf.h>,
// so the declaration is invisible to bindgen regardless of build
// mode. The C symbol is genuinely compiled into both libraries
// (confirmed via boringssl_prefix_symbols.h, which renames it like
// any other real exported function), so this shim reaches it
// directly. Including the crate's own public <openssl/sshkdf.h>
// (rather than declaring SSHKDF ourselves) means the crate's
// boringssl_prefix_symbols.h - transitively included via base.h -
// rewrites the SSHKDF call to that build's real, versioned symbol
// name (e.g. aws_lc_fips_0_14_2_SSHKDF) automatically, so this file
// never has to hardcode it.
#include <openssl/sshkdf.h>

int kryoptic_awslc_sshkdf(const EVP_MD *evp_md,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *xcghash, size_t xcghash_len,
                           const uint8_t *session_id, size_t session_id_len,
                           char type,
                           uint8_t *out, size_t out_len) {
    return SSHKDF(evp_md, key, key_len, xcghash, xcghash_len,
                   session_id, session_id_len, type, out, out_len);
}
