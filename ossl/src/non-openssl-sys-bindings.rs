// handwritten OpenSSL constants

pub const OSSL_PARAM_UTF8_STRING: u32 = 4;

// Signature + AsymCipher
pub const OSSL_SIGNATURE_PARAM_CONTEXT_STRING: &[u8; 15] = b"context-string\0";
pub const OSSL_SIGNATURE_PARAM_DETERMINISTIC: &[u8; 14] = b"deterministic\0";
pub const OSSL_SIGNATURE_PARAM_PSS_SALTLEN: &[u8; 8] = b"saltlen\0";
pub const OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING: &[u8; 17] =
    b"message-encoding\0";
pub const OSSL_SIGNATURE_PARAM_MGF1_DIGEST: &[u8; 12] = b"mgf1-digest\0";
pub const OSSL_SIGNATURE_PARAM_DIGEST: &[u8; 7] = b"digest\0";
pub const OSSL_SIGNATURE_PARAM_PAD_MODE: &[u8; 9] = b"pad-mode\0";
pub const OSSL_PKEY_RSA_PAD_MODE_PSS: &[u8; 4] = b"pss\0";
pub const OSSL_PKEY_RSA_PAD_MODE_NONE: &[u8; 5] = b"none\0";
pub const OSSL_PKEY_RSA_PAD_MODE_PKCSV15: &[u8; 6] = b"pkcs1\0";
pub const OSSL_PKEY_RSA_PAD_MODE_OAEP: &[u8; 5] = b"oaep\0";

pub const OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL: &[u8; 11] = b"oaep-label\0";
pub const OSSL_PKEY_PARAM_PAD_MODE: &[u8; 9] = b"pad-mode\0";
pub const OSSL_PKEY_PARAM_MGF1_DIGEST: &[u8; 12] = b"mgf1-digest\0";
pub const OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST: &[u8; 7] = b"digest\0";

// Digest
pub const OSSL_DIGEST_NAME_MD5: &[u8; 4] = b"MD5\0";
pub const OSSL_DIGEST_NAME_SHA1: &[u8; 5] = b"SHA1\0";
pub const OSSL_DIGEST_NAME_SHA2_224: &[u8; 9] = b"SHA2-224\0";
pub const OSSL_DIGEST_NAME_SHA2_256: &[u8; 9] = b"SHA2-256\0";
pub const OSSL_DIGEST_NAME_SHA2_256_192: &[u8; 13] = b"SHA2-256/192\0";
pub const OSSL_DIGEST_NAME_SHA2_384: &[u8; 9] = b"SHA2-384\0";
pub const OSSL_DIGEST_NAME_SHA2_512: &[u8; 9] = b"SHA2-512\0";
pub const OSSL_DIGEST_NAME_SHA2_512_224: &[u8; 13] = b"SHA2-512/224\0";
pub const OSSL_DIGEST_NAME_SHA2_512_256: &[u8; 13] = b"SHA2-512/256\0";
pub const OSSL_DIGEST_NAME_SHA3_224: &[u8; 9] = b"SHA3-224\0";
pub const OSSL_DIGEST_NAME_SHA3_256: &[u8; 9] = b"SHA3-256\0";
pub const OSSL_DIGEST_NAME_SHA3_384: &[u8; 9] = b"SHA3-384\0";
pub const OSSL_DIGEST_NAME_SHA3_512: &[u8; 9] = b"SHA3-512\0";

// Rand
pub const OSSL_RAND_PARAM_STRENGTH: &[u8; 9] = b"strength\0";
pub const OSSL_RAND_PARAM_MAX_REQUEST: &[u8; 12] = b"max_request\0";
pub const OSSL_RAND_PARAM_STATE: &[u8; 6] = b"state\0";

pub const OSSL_DRBG_PARAM_DIGEST: &[u8; 7] = b"digest\0";
pub const OSSL_DRBG_PARAM_MAC: &[u8; 4] = b"mac\0";
pub const OSSL_DRBG_PARAM_MAX_ADINLEN: &[u8; 12] = b"max_adinlen\0";
pub const OSSL_DRBG_PARAM_MAX_ENTROPYLEN: &[u8; 15] = b"max_entropylen\0";
pub const OSSL_DRBG_PARAM_MAX_NONCELEN: &[u8; 13] = b"max_noncelen\0";
pub const OSSL_DRBG_PARAM_MAX_PERSLEN: &[u8; 12] = b"max_perslen\0";
pub const OSSL_DRBG_PARAM_MIN_ENTROPYLEN: &[u8; 15] = b"min_entropylen\0";
pub const OSSL_DRBG_PARAM_MIN_NONCELEN: &[u8; 13] = b"min_noncelen\0";
pub const OSSL_DRBG_PARAM_RESEED_COUNTER: &[u8; 15] = b"reseed_counter\0";
pub const OSSL_DRBG_PARAM_RESEED_REQUESTS: &[u8; 16] = b"reseed_requests\0";
pub const OSSL_DRBG_PARAM_RESEED_TIME: &[u8; 12] = b"reseed_time\0";
pub const OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL: &[u8; 21] =
    b"reseed_time_interval\0";

// Pkey
pub const OSSL_PKEY_PARAM_GROUP_NAME: &[u8; 6] = b"group\0";
pub const OSSL_PKEY_PARAM_PUB_KEY: &[u8; 4] = b"pub\0";
pub const OSSL_PKEY_PARAM_PRIV_KEY: &[u8; 5] = b"priv\0";

pub const OSSL_PKEY_PARAM_RSA_COEFFICIENT1: &[u8; 17] = b"rsa-coefficient1\0";
pub const OSSL_PKEY_PARAM_RSA_COEFFICIENT2: &[u8; 17] = b"rsa-coefficient2\0";
pub const OSSL_PKEY_PARAM_RSA_E: &[u8; 2] = b"e\0";
pub const OSSL_PKEY_PARAM_RSA_EXPONENT1: &[u8; 14] = b"rsa-exponent1\0";
pub const OSSL_PKEY_PARAM_RSA_EXPONENT2: &[u8; 14] = b"rsa-exponent2\0";
pub const OSSL_PKEY_PARAM_RSA_FACTOR1: &[u8; 12] = b"rsa-factor1\0";
pub const OSSL_PKEY_PARAM_RSA_FACTOR2: &[u8; 12] = b"rsa-factor2\0";
pub const OSSL_PKEY_PARAM_RSA_D: &[u8; 2] = b"d\0";
pub const OSSL_PKEY_PARAM_RSA_N: &[u8; 2] = b"n\0";
pub const OSSL_PKEY_PARAM_RSA_BITS: &[u8; 5] = b"bits\0";
pub const OSSL_PKEY_PARAM_ML_KEM_SEED: &[u8; 5] = b"seed\0";
pub const OSSL_PKEY_PARAM_ML_DSA_SEED: &[u8; 5] = b"seed\0";
pub const OSSL_PKEY_PARAM_FFC_G: &[u8; 2] = b"g\0";
pub const OSSL_PKEY_PARAM_FFC_P: &[u8; 2] = b"p\0";
pub const OSSL_PKEY_PARAM_FFC_Q: &[u8; 2] = b"q\0";
pub const OSSL_PKEY_PARAM_FFC_PBITS: &[u8; 6] = b"pbits\0";

pub const OSSL_EXCHANGE_PARAM_KDF_OUTLEN: &[u8; 11] = b"kdf-outlen\0";
pub const OSSL_EXCHANGE_PARAM_KDF_TYPE: &[u8; 9] = b"kdf-type\0";
pub const OSSL_EXCHANGE_PARAM_KDF_UKM: &[u8; 8] = b"kdf-ukm\0";
pub const OSSL_EXCHANGE_PARAM_KDF_DIGEST: &[u8; 11] = b"kdf-digest\0";
pub const OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE: &[u8; 19] =
    b"ecdh-cofactor-mode\0";

// Derive
pub const OSSL_KDF_PARAM_CIPHER: &[u8; 7] = b"cipher\0";
pub const OSSL_KDF_PARAM_DIGEST: &[u8; 7] = b"digest\0";
pub const OSSL_KDF_PARAM_INFO: &[u8; 5] = b"info\0";
pub const OSSL_KDF_PARAM_ITER: &[u8; 5] = b"iter\0";
pub const OSSL_KDF_PARAM_KEY: &[u8; 4] = b"key\0";
pub const OSSL_KDF_PARAM_MAC: &[u8; 4] = b"mac\0";
pub const OSSL_KDF_PARAM_MODE: &[u8; 5] = b"mode\0";
pub const OSSL_KDF_PARAM_PASSWORD: &[u8; 5] = b"pass\0";
pub const OSSL_KDF_PARAM_SALT: &[u8; 5] = b"salt\0";
pub const OSSL_KDF_PARAM_SEED: &[u8; 5] = b"seed\0";

pub const OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR: &[u8; 14] = b"use-separator\0";
pub const OSSL_KDF_PARAM_KBKDF_USE_L: &[u8; 6] = b"use-l\0";
pub const OSSL_KDF_PARAM_KBKDF_R: &[u8; 2] = b"r\0";

pub const OSSL_KDF_PARAM_SSHKDF_SESSION_ID: &[u8; 11] = b"session_id\0";
pub const OSSL_KDF_PARAM_SSHKDF_TYPE: &[u8; 5] = b"type\0";
pub const OSSL_KDF_PARAM_SSHKDF_XCGHASH: &[u8; 8] = b"xcghash\0";

pub const OSSL_KDF_NAME_HKDF: &[u8; 5] = b"HKDF\0";
pub const OSSL_KDF_NAME_PBKDF2: &[u8; 7] = b"PBKDF2\0";
pub const OSSL_KDF_NAME_KBKDF: &[u8; 6] = b"KBKDF\0";
pub const OSSL_KDF_NAME_X963KDF: &[u8; 8] = b"X963KDF\0";
pub const OSSL_KDF_NAME_SSHKDF: &[u8; 7] = b"SSHKDF\0";
pub const OSSL_KDF_NAME_SSKDF: &[u8; 6] = b"SSKDF\0";

pub const EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND: c_int = 0;
pub const EVP_KDF_HKDF_MODE_EXTRACT_ONLY: c_int = 1;
pub const EVP_KDF_HKDF_MODE_EXPAND_ONLY: c_int = 2;

// Cipher
pub const EVP_CTRL_AEAD_GET_TAG: u32 = 16;
pub const EVP_CTRL_AEAD_SET_TAG: u32 = 17;
pub const EVP_CTRL_AEAD_SET_IVLEN: u32 = 9;

pub const OSSL_CIPHER_PARAM_CTS_MODE: &[u8; 9] = b"cts_mode\0";

pub const OSSL_CIPHER_CTS_MODE_CS1: &[u8; 4] = b"CS1\0";
pub const OSSL_CIPHER_CTS_MODE_CS2: &[u8; 4] = b"CS2\0";
pub const OSSL_CIPHER_CTS_MODE_CS3: &[u8; 4] = b"CS3\0";

pub const LN_aes_128_ecb: &[u8; 12] = b"aes-128-ecb\0";
pub const LN_aes_128_cbc: &[u8; 12] = b"aes-128-cbc\0";
pub const LN_aes_128_ofb128: &[u8; 12] = b"aes-128-ofb\0";
pub const LN_aes_128_cfb128: &[u8; 12] = b"aes-128-cfb\0";
pub const LN_aes_128_gcm: &[u8; 12] = b"aes-128-gcm\0";
pub const LN_aes_128_ccm: &[u8; 12] = b"aes-128-ccm\0";
pub const LN_aes_192_ecb: &[u8; 12] = b"aes-192-ecb\0";
pub const LN_aes_192_cbc: &[u8; 12] = b"aes-192-cbc\0";
pub const LN_aes_192_ofb128: &[u8; 12] = b"aes-192-ofb\0";
pub const LN_aes_192_cfb128: &[u8; 12] = b"aes-192-cfb\0";
pub const LN_aes_192_gcm: &[u8; 12] = b"aes-192-gcm\0";
pub const LN_aes_192_ccm: &[u8; 12] = b"aes-192-ccm\0";
pub const LN_aes_256_ecb: &[u8; 12] = b"aes-256-ecb\0";
pub const LN_aes_256_cbc: &[u8; 12] = b"aes-256-cbc\0";
pub const LN_aes_256_ofb128: &[u8; 12] = b"aes-256-ofb\0";
pub const LN_aes_256_cfb128: &[u8; 12] = b"aes-256-cfb\0";
pub const LN_aes_256_gcm: &[u8; 12] = b"aes-256-gcm\0";
pub const LN_aes_256_ccm: &[u8; 12] = b"aes-256-ccm\0";
pub const LN_aes_128_xts: &[u8; 12] = b"aes-128-xts\0";
pub const LN_aes_256_xts: &[u8; 12] = b"aes-256-xts\0";
pub const LN_aes_128_cfb1: &[u8; 13] = b"aes-128-cfb1\0";
pub const LN_aes_192_cfb1: &[u8; 13] = b"aes-192-cfb1\0";
pub const LN_aes_256_cfb1: &[u8; 13] = b"aes-256-cfb1\0";
pub const LN_aes_128_cfb8: &[u8; 13] = b"aes-128-cfb8\0";
pub const LN_aes_192_cfb8: &[u8; 13] = b"aes-192-cfb8\0";
pub const LN_aes_256_cfb8: &[u8; 13] = b"aes-256-cfb8\0";
pub const LN_aes_128_ctr: &[u8; 12] = b"aes-128-ctr\0";
pub const LN_aes_192_ctr: &[u8; 12] = b"aes-192-ctr\0";
pub const LN_aes_256_ctr: &[u8; 12] = b"aes-256-ctr\0";
pub const LN_aes_128_ocb: &[u8; 12] = b"aes-128-ocb\0";
pub const LN_aes_192_ocb: &[u8; 12] = b"aes-192-ocb\0";
pub const LN_aes_256_ocb: &[u8; 12] = b"aes-256-ocb\0";
pub const LN_aes_128_cbc_hmac_sha1: &[u8; 22] = b"aes-128-cbc-hmac-sha1\0";
pub const LN_aes_192_cbc_hmac_sha1: &[u8; 22] = b"aes-192-cbc-hmac-sha1\0";
pub const LN_aes_256_cbc_hmac_sha1: &[u8; 22] = b"aes-256-cbc-hmac-sha1\0";
pub const LN_aes_128_cbc_hmac_sha256: &[u8; 24] = b"aes-128-cbc-hmac-sha256\0";
pub const LN_aes_192_cbc_hmac_sha256: &[u8; 24] = b"aes-192-cbc-hmac-sha256\0";
pub const LN_aes_256_cbc_hmac_sha256: &[u8; 24] = b"aes-256-cbc-hmac-sha256\0";
pub const LN_aes_128_siv: &[u8; 12] = b"aes-128-siv\0";
pub const LN_aes_192_siv: &[u8; 12] = b"aes-192-siv\0";
pub const LN_aes_256_siv: &[u8; 12] = b"aes-256-siv\0";

// Mac
pub const OSSL_MAC_PARAM_CIPHER: &[u8; 7] = b"cipher\0";
pub const OSSL_MAC_PARAM_DIGEST: &[u8; 7] = b"digest\0";

pub const OSSL_MAC_NAME_CMAC: &[u8; 5] = b"CMAC\0";
pub const OSSL_MAC_NAME_HMAC: &[u8; 5] = b"HMAC\0";

// Old openssl-sys is missing these
pub const EVP_PKEY_PRIVATE_KEY: c_int = 133;
pub const EVP_PKEY_PUBLIC_KEY: c_int = 134;
pub const EVP_PKEY_KEYPAIR: c_int = 135;

pub const EVP_PKEY_ML_DSA_44: c_int = 1457;
pub const EVP_PKEY_ML_DSA_65: c_int = 1458;
pub const EVP_PKEY_ML_DSA_87: c_int = 1459;
pub const EVP_PKEY_SLH_DSA_SHA2_128S: c_int = 1460;
pub const EVP_PKEY_SLH_DSA_SHA2_128F: c_int = 1461;
pub const EVP_PKEY_SLH_DSA_SHA2_192S: c_int = 1462;
pub const EVP_PKEY_SLH_DSA_SHA2_192F: c_int = 1463;
pub const EVP_PKEY_SLH_DSA_SHA2_256S: c_int = 1464;
pub const EVP_PKEY_SLH_DSA_SHA2_256F: c_int = 1465;
pub const EVP_PKEY_SLH_DSA_SHAKE_128S: c_int = 1466;
pub const EVP_PKEY_SLH_DSA_SHAKE_128F: c_int = 1467;
pub const EVP_PKEY_SLH_DSA_SHAKE_192S: c_int = 1468;
pub const EVP_PKEY_SLH_DSA_SHAKE_192F: c_int = 1469;
pub const EVP_PKEY_SLH_DSA_SHAKE_256S: c_int = 1470;
pub const EVP_PKEY_SLH_DSA_SHAKE_256F: c_int = 1471;
