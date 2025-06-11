// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements TLS Key Derivation Functions (KDF) and MAC
//! operations, primarily focusing on the TLS 1.2 PRF (Pseudo-Random
//! Function) based on HMAC, as defined in
//! [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246).

use std::fmt::Debug;

#[cfg(feature = "fips")]
use crate::attribute::Attribute;
use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::hmac::{hash_to_hmac_mech, register_mechs_only};
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::{bytes_to_slice, bytes_to_vec, cast_params, CK_ULONG_SIZE};
use crate::object::{Object, ObjectFactories};

use constant_time_eq::constant_time_eq;
use once_cell::sync::Lazy;

#[cfg(feature = "fips")]
use crate::fips::set_fips_error_state;
#[cfg(feature = "fips")]
use crate::hmac::test_get_hmac;

/// Macro to safely get a boolean attribute value or a default for a
/// specific attribute of a key object.
///
/// Returns an error if the attribute is missing and no default is provided.
///
/// Converts Rust bool to CK_BOOL.
macro_rules! as_ck_bbool {
    ($key:expr, $attr:expr, $def:expr) => {{
        let b = match $key.get_attr_as_bool($attr) {
            Ok(v) => v,
            Err(_) => {
                if let Some(b) = $def {
                    b
                } else {
                    return Err(CKR_GENERAL_ERROR)?;
                }
            }
        };
        if b {
            CK_TRUE
        } else {
            CK_FALSE
        }
    }};
}

pub const TLS_MASTER_SECRET_SIZE: CK_ULONG = 48;
const TLS_RANDOM_SEED_SIZE: usize = 32;
/// List of mechanisms allowed for a key derived as a TLS Master Secret.
const TLS_MASTER_SECRET_ALLOWED_MECHS: [CK_ULONG; 6] = [
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_KEY_SAFE_DERIVE,
    CKM_TLS_KDF,
    CKM_TLS12_KDF, /* deprecated alias for CKM_TLS_KDF */
    CKM_TLS_MAC,
    CKM_TLS12_MAC, /* deprecated alias for CKM_TLS_MAC */
];
const TLS_MASTER_SECRET_LABEL: &[u8; 13] = b"master secret";
const TLS_KEY_EXPANSION_LABEL: &[u8; 13] = b"key expansion";
const TLS_SERVER_FINISHED: &[u8; 15] = b"server finished";
const TLS_CLIENT_FINISHED: &[u8; 15] = b"client finished";
#[cfg(feature = "pkcs11_3_2")]
const TLS_EXTENDED_MASTER_SECRET_LABEL: &[u8; 22] = b"extended master secret";

/// Represents the TLS Pseudo-Random Function (PRF) based on HMAC
/// (RFC 5246 Section 5)
#[derive(Debug)]
struct TLSPRF {
    op: Box<dyn Mac>,
}

impl TLSPRF {
    /// Initializes a new TLS PRF instance using the specified HMAC mechanism
    fn init(
        key: &Object,
        mech: &Box<dyn Mechanism>,
        prf: CK_MECHANISM_TYPE,
    ) -> Result<TLSPRF> {
        Ok(TLSPRF {
            op: mech.mac_new(
                &CK_MECHANISM {
                    mechanism: prf,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
                key,
                CKF_DERIVE,
            )?,
        })
    }

    /// Computes the TLS PRF output (P_hash function) for a given seed and
    /// required length.
    ///
    /// Implements the P_hash expansion:
    ///     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    ///                            HMAC_hash(secret, A(2) + seed) + ...
    ///     where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
    fn finish(&mut self, seed: &Vec<u8>, reqlen: usize) -> Result<Vec<u8>> {
        let maclen = self.op.mac_len()?;

        let mut ax = vec![0u8; maclen];
        self.op.mac_update(seed.as_slice())?;
        self.op.mac_final(ax.as_mut_slice())?;
        /* ax = A(1) */

        /* use a buffer length that is a multiple of maclen,
         * then truncate to actual reqlen before returning */
        let mut out = vec![0u8; ((reqlen + maclen - 1) / maclen) * maclen];
        let mut outlen = 0;
        while outlen < reqlen {
            self.op.reset()?;
            self.op.mac_update(ax.as_slice())?;
            self.op.mac_update(seed.as_slice())?;
            self.op.mac_final(&mut out[outlen..(outlen + maclen)])?;

            outlen += maclen;

            if outlen < reqlen {
                /* ax = A(x + 1) */
                self.op.reset()?;
                self.op.mac_update(ax.as_slice())?;
                self.op.mac_final(ax.as_mut_slice())?;
            }
        }
        out.resize(reqlen, 0);
        Ok(out)
    }
}

/// Checks if a given HMAC mechanism is FIPS approved for use in TLS KDF.
#[cfg(feature = "fips")]
fn is_hmac_fips_approved(prf: CK_MECHANISM_TYPE) -> Option<bool> {
    match prf {
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC => Some(true),
        _ => Some(false),
    }
}

/// Test helper function to directly invoke the TLS PRF logic.
#[cfg(test)]
pub fn test_tlsprf(
    key: &Object,
    mech: &Box<dyn Mechanism>,
    prf: CK_MECHANISM_TYPE,
    seed: &Vec<u8>,
    reqlen: usize,
) -> Result<Vec<u8>> {
    let mut tlsprf = TLSPRF::init(key, mech, prf)?;
    tlsprf.finish(seed, reqlen)
}

/// Holds the result of the FIPS self-test for the TLS PRF.
#[cfg(feature = "fips")]
struct FIPSSelftest {
    result: CK_RV,
}

/// Static Lazy variable to run FIPS Known Answer Tests (KATs) for the TLS PRF
/// on initialization
///
/// Uses a test vector from OpenSSL.
///
/// If the calculated output does not match the expected output, it sets the
/// FIPS error state and stores `CKR_FIPS_SELF_TEST_FAILED` in
/// [FIPSSelfTest.result].
#[cfg(feature = "fips")]
static TLS_PRF_SELFTEST: Lazy<FIPSSelftest> = Lazy::new(|| {
    let mut status = FIPSSelftest {
        result: CKR_FIPS_SELF_TEST_FAILED,
    };

    /* Test vector taken from OpenSSL selftest */
    let prf: CK_MECHANISM_TYPE = CKM_SHA256_HMAC;
    let secret = hex::decode(
        "202c88c00f84a17a20027079604787461176455539e705be\
         730890602c289a5001e34eeb3a043e5d52a65e66125188bf",
    )
    .unwrap();
    let label: &[u8] = b"key expansion";
    let randoms = hex::decode(
        "ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868\
         62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616",
    )
    .unwrap();
    let mut seed = Vec::<u8>::with_capacity(label.len() + randoms.len());
    seed.extend_from_slice(&label);
    seed.extend_from_slice(&randoms);

    let expect = hex::decode(
        "d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531\
         016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f\
         6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f\
         1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928",
    )
    .unwrap();

    /* mock key */
    let mut key = Object::new();
    key.set_attr(Attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))
        .unwrap();
    key.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))
        .unwrap();
    key.set_attr(Attribute::from_bytes(CKA_VALUE, secret.clone()))
        .unwrap();
    key.set_attr(Attribute::from_ulong(
        CKA_VALUE_LEN,
        secret.len() as CK_ULONG,
    ))
    .unwrap();
    key.set_attr(Attribute::from_bool(CKA_DERIVE, true))
        .unwrap();

    let mech = test_get_hmac(prf);

    let mut tlsprf = match TLSPRF::init(&key, &mech, prf) {
        Ok(a) => a,
        Err(_) => return status,
    };
    let out = match tlsprf.finish(&seed, expect.len()) {
        Ok(a) => a,
        Err(_) => return status,
    };
    if out == expect {
        status.result = CKR_OK;
    }
    if status.result == CKR_FIPS_SELF_TEST_FAILED {
        set_fips_error_state();
    }
    status
});

/// Represents a TLS Key Derivation Function (KDF) operation
///
/// This handles mechanisms like `CKM_TLS12_MASTER_KEY_DERIVE`,
/// `CKM_TLS12_KEY_AND_MAC_DERIVE`, and `CKM_TLS_KDF`.
#[derive(Debug)]
pub struct TLSKDFOperation {
    /// Tracks if the derive operation has been completed
    finalized: bool,
    /// The specific PKCS#11 TLS KDF mechanism being used
    mech: CK_MECHANISM_TYPE,
    /// Client random bytes.
    client_random: Vec<u8>,
    /// Server random bytes.
    server_random: Vec<u8>,
    /// Full session hash for EMS.
    #[cfg(feature = "pkcs11_3_2")]
    session_hash: Vec<u8>,
    /// Optional pointer to store the negotiated TLS version (used by
    /// CKM_TLS12_MASTER_KEY_DERIVE)
    version: Option<*mut CK_VERSION>,
    /// The underlying PRF mechanism (e.g., CKM_SHA256_HMAC)
    prf: CK_MECHANISM_TYPE,
    /// Label used in the PRF seed (e.g., "master secret", "key expansion")
    label: &'static [u8],
    /// Optional context data used in the PRF seed (for CKM_TLS_KDF)
    context: &'static [u8],
    /// Requested length for derived MAC keys (in bytes)
    maclen: CK_ULONG,
    /// Requested length for derived encryption keys (in bytes)
    keylen: CK_ULONG,
    /// Required length for derived IVs (in bytes)
    ivlen: CK_ULONG,
    /// Optional pointer to the output structure for key material
    /// (CKM_TLS12_KEY_AND_MAC_DERIVE)
    mat_out: Option<*mut CK_SSL3_KEY_MAT_OUT>,
    /// Option that holds the FIPS indicator
    /// - Some(true) = approved
    /// - Some(false) = not-approved
    /// - None = undetermined
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

unsafe impl Send for TLSKDFOperation {}
unsafe impl Sync for TLSKDFOperation {}

impl TLSKDFOperation {
    /// Creates a new TLS KDF operation based on the provided mechanism
    ///
    /// Dispatches to specific constructors based on the mechanism type.
    ///
    /// Errors out if FIPS self-tests result is an error when the "fips"
    /// feature is enabled.
    pub fn new(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        #[cfg(feature = "fips")]
        if TLS_PRF_SELFTEST.result != CKR_OK {
            return Err(TLS_PRF_SELFTEST.result)?;
        }

        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE | CKM_TLS12_MASTER_KEY_DERIVE_DH => {
                Self::new_tls12_mk_derive(mech)
            }
            CKM_TLS12_KEY_AND_MAC_DERIVE | CKM_TLS12_KEY_SAFE_DERIVE => {
                Self::new_tls12_keymac_derive(mech)
            }
            CKM_TLS12_KDF | CKM_TLS_KDF => {
                Self::new_tls_generic_key_derive(mech)
            }
            #[cfg(feature = "pkcs11_3_2")]
            CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE
            | CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH => {
                Self::new_tls12_ems_derive(mech)
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Constructor for the `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` and
    /// `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH` mechanisms
    ///
    /// Parses `CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS`, validates inputs and sets up the
    /// operation context for deriving the extended master secret
    #[cfg(feature = "pkcs11_3_2")]
    fn new_tls12_ems_derive(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        let params =
            cast_params!(mech, CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS);

        let prf = match hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        let session_hash =
            bytes_to_vec!(params.pSessionHash, params.ulSessionHashLen);

        // The pVersion field of the structure must be set to NULL_PTR since the version
        // number is not embedded in the "pre_master" key as it is for RSA-like cipher suites.
        if mech.mechanism == CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
            && !params.pVersion.is_null()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let version = if params.pVersion.is_null() {
            None
        } else {
            Some(params.pVersion)
        };

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: Vec::new(),
            server_random: Vec::new(),
            session_hash: session_hash,
            version: version,
            prf: prf,
            label: TLS_EXTENDED_MASTER_SECRET_LABEL,
            context: &[],
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
            #[cfg(feature = "fips")]
            fips_approved: is_hmac_fips_approved(prf),
        })
    }

    /// Constructor for the `CKM_TLS12_MASTER_KEY_DERIVE` mechanism
    ///
    /// Parses `CK_TLS12_MASTER_KEY_DERIVE_PARAMS`, validates inputs, and sets
    /// up the operation context for deriving the master secret.
    fn new_tls12_mk_derive(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS12_MASTER_KEY_DERIVE_PARAMS);

        let clirand = bytes_to_vec!(
            params.RandomInfo.pClientRandom,
            params.RandomInfo.ulClientRandomLen
        );
        let srvrand = bytes_to_vec!(
            params.RandomInfo.pServerRandom,
            params.RandomInfo.ulServerRandomLen
        );

        if clirand.len() != TLS_RANDOM_SEED_SIZE
            || srvrand.len() != TLS_RANDOM_SEED_SIZE
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let prf = match hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        // The pVersion field of the structure must be set to NULL_PTR since the version
        // number is not embedded in the "pre_master" key as it is for RSA-like cipher suites.
        if mech.mechanism == CKM_TLS12_MASTER_KEY_DERIVE_DH
            && !params.pVersion.is_null()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let version = if params.pVersion.is_null() {
            None
        } else {
            Some(params.pVersion)
        };

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            #[cfg(feature = "pkcs11_3_2")]
            session_hash: Vec::new(),
            version: version,
            prf: prf,
            label: TLS_MASTER_SECRET_LABEL,
            context: &[],
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
            #[cfg(feature = "fips")]
            fips_approved: is_hmac_fips_approved(prf),
        })
    }

    /// Constructor for `CKM_TLS12_KEY_AND_MAC_DERIVE` and
    /// `CKM_TLS12_KEY_SAFE_DERIVE`
    ///
    /// Parses `CK_TLS12_KEY_MAT_PARAMS`, calculates required output lengths,
    /// validates inputs (randoms, export flag), checks the output structure
    /// pointer, and sets up the operation context for deriving MAC keys,
    /// write keys, and IVs.
    fn new_tls12_keymac_derive(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS12_KEY_MAT_PARAMS);

        let maclen = params.ulMacSizeInBits / 8;
        let keylen = params.ulKeySizeInBits / 8;
        let ivlen = if mech.mechanism == CKM_TLS12_KEY_SAFE_DERIVE {
            0
        } else {
            params.ulIVSizeInBits / 8
        };

        if params.bIsExport != CK_FALSE {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let clirand = bytes_to_vec!(
            params.RandomInfo.pClientRandom,
            params.RandomInfo.ulClientRandomLen
        );
        let srvrand = bytes_to_vec!(
            params.RandomInfo.pServerRandom,
            params.RandomInfo.ulServerRandomLen
        );

        if clirand.len() != TLS_RANDOM_SEED_SIZE
            || srvrand.len() != TLS_RANDOM_SEED_SIZE
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let prf = match hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        if params.pReturnedKeyMaterial.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            #[cfg(feature = "pkcs11_3_2")]
            session_hash: Vec::new(),
            version: None,
            prf: prf,
            label: TLS_KEY_EXPANSION_LABEL,
            context: &[],
            maclen: maclen,
            keylen: if keylen > 0 {
                keylen
            } else {
                TLS_MASTER_SECRET_SIZE
            },
            ivlen: ivlen,
            mat_out: Some(params.pReturnedKeyMaterial),
            #[cfg(feature = "fips")]
            fips_approved: is_hmac_fips_approved(prf),
        })
    }

    /// Constructor for `CKM_TLS_KDF` (and its alias `CKM_TLS12_KDF`)
    ///
    /// Parses `CK_TLS_KDF_PARAMS`, validates inputs (label, randoms), and
    /// sets up the operation context for generic labeled PRF derivation.
    fn new_tls_generic_key_derive(
        mech: &CK_MECHANISM,
    ) -> Result<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS_KDF_PARAMS);

        if params.ulLabelLength == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let clirand = bytes_to_vec!(
            params.RandomInfo.pClientRandom,
            params.RandomInfo.ulClientRandomLen
        );
        let srvrand = bytes_to_vec!(
            params.RandomInfo.pServerRandom,
            params.RandomInfo.ulServerRandomLen
        );

        if clirand.len() != TLS_RANDOM_SEED_SIZE
            || srvrand.len() != TLS_RANDOM_SEED_SIZE
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let prf = match hash_to_hmac_mech(params.prfMechanism) {
            Ok(h) => h,
            Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            #[cfg(feature = "pkcs11_3_2")]
            session_hash: Vec::new(),
            version: None,
            prf: prf,
            label: bytes_to_slice!(params.pLabel, params.ulLabelLength, u8),
            context: bytes_to_slice!(
                params.pContextData,
                params.ulContextDataLength,
                u8
            ),
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
            #[cfg(feature = "fips")]
            fips_approved: is_hmac_fips_approved(prf),
        })
    }

    /// Verifies that the base key object is suitable for TLS KDF operations
    ///
    /// Checks CKA_CLASS, CKA_KEY_TYPE, CKA_DERIVE, and that CKA_VALUE_LEN
    /// matches exactly TLS_MASTER_SECRET_SIZE.
    fn verify_key(&self, key: &Object) -> Result<()> {
        key.check_key_ops(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_DERIVE)?;
        match key.get_attr(CKA_VALUE_LEN) {
            Some(a) => match a.to_ulong() {
                Ok(l) => {
                    if l != TLS_MASTER_SECRET_SIZE {
                        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
                    }
                    Ok(())
                }
                Err(_) => return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?,
            },
            None => return Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Verifies and augments the template attributes for deriving a TLS master
    /// secret key
    ///
    /// Ensures CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, and
    /// CKA_ALLOWED_MECHANISMS are consistent with a standard TLS master secret.
    ///
    /// Adds missing defaults.
    fn verify_mk_template<'a>(
        &self,
        template: &'a [CK_ATTRIBUTE],
    ) -> Result<CkAttrs<'a>> {
        /* augment template, then check that it has all the right values */
        let allowed = unsafe {
            std::mem::transmute::<&[CK_ULONG; 6], &[u8; 6 * CK_ULONG_SIZE]>(
                &TLS_MASTER_SECRET_ALLOWED_MECHS,
            )
        };
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
        tmpl.add_missing_ulong(CKA_VALUE_LEN, &TLS_MASTER_SECRET_SIZE);
        tmpl.add_missing_slice(CKA_ALLOWED_MECHANISMS, allowed)?;
        tmpl.add_missing_bool(CKA_SIGN, &CK_TRUE);
        tmpl.add_missing_bool(CKA_VERIFY, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DERIVE, &CK_TRUE);
        for attr in tmpl.as_slice() {
            match attr.type_ {
                CKA_CLASS => {
                    let val = attr.to_ulong()?;
                    if val != CKO_SECRET_KEY {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKA_KEY_TYPE => {
                    let val = attr.to_ulong()?;
                    if val != CKK_GENERIC_SECRET {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKA_VALUE_LEN => {
                    let val = attr.to_ulong()?;
                    if val != TLS_MASTER_SECRET_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKA_ALLOWED_MECHANISMS => {
                    let val = attr.to_slice()?;
                    if val != allowed {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                _ => (),
            }
        }
        Ok(tmpl)
    }

    /// Constructs the seed input for the TLS PRF calculation
    ///
    /// Concatenates label + client_random + server_random
    /// or label + server_random + client_random,
    /// plus optional context data.
    ///
    /// The client secret comes first if `cli_first` is true.
    fn tls_prf_seed(&self, cli_first: bool) -> Vec<u8> {
        let mut seed = Vec::<u8>::with_capacity(
            self.label.len()
                + self.client_random.len()
                + self.server_random.len()
                + self.context.len(),
        );
        seed.extend_from_slice(self.label);
        if cli_first {
            seed.extend_from_slice(self.client_random.as_slice());
            seed.extend_from_slice(self.server_random.as_slice());
        } else {
            seed.extend_from_slice(self.server_random.as_slice());
            seed.extend_from_slice(self.client_random.as_slice());
        }
        if self.context.len() > 0 {
            seed.extend_from_slice(self.context);
        }
        seed
    }

    /// Constructs the seed input for the TLS PRF calculation of EMS
    ///
    /// Concatenates label + session hash.
    #[cfg(feature = "pkcs11_3_2")]
    fn tls_prf_seed_ems(&self) -> Vec<u8> {
        let mut seed = Vec::<u8>::with_capacity(
            self.label.len() + self.session_hash.len(),
        );
        seed.extend_from_slice(self.label);
        seed.extend_from_slice(self.session_hash.as_slice());
        seed
    }

    /// Performs the derivation for `CKM_TLS12_MASTER_KEY_DERIVE` or
    /// `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE`
    ///
    /// Verifies the base key and template.
    ///
    /// Calls the TLS PRF with the "master secret" label and combined randoms
    /// or with the "extended master secret" and session hash.
    ///
    /// Sets the derived key value in the new object.
    ///
    /// Optionally fills the TLS version structure provided in the mechanism
    /// parameters. This is not needed for the *_DH variants.
    fn derive_master_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let tmpl = self.verify_mk_template(template)?;
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = match self.mech {
            #[cfg(feature = "pkcs11_3_2")]
            CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE
            | CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH => {
                self.tls_prf_seed_ems()
            }
            CKM_TLS12_MASTER_KEY_DERIVE | CKM_TLS12_MASTER_KEY_DERIVE_DH => {
                self.tls_prf_seed(true)
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let dkmlen = TLS_MASTER_SECRET_SIZE as usize;
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

        factory.as_secret_key_factory()?.set_key(&mut dkey, dkm)?;

        /* fill in the version if all went well */
        if let Some(version) = self.version {
            let mut maj: CK_BYTE = 0xff;
            let mut min: CK_BYTE = 0xff;
            /* do not leak bytes for long term keys, openssl really only
             * uses ephemeral session keys, so there is no business in
             * returning bytes from a long term stored token key */
            if !key.is_token() {
                let secret = match key.get_attr(CKA_VALUE) {
                    None => return Err(CKR_GENERAL_ERROR)?,
                    Some(val) => val.to_bytes()?,
                };
                maj = secret[0];
                min = secret[1];
            }
            unsafe {
                (*version).major = maj;
                (*version).minor = min;
            }
        }

        Ok(vec![dkey])
    }

    /// Verifies and augments the template for deriving TLS key expansion
    /// keys (write/MAC keys)
    ///
    /// Ensures consistency for attributes like CKA_CLASS, CKA_KEY_TYPE,
    /// CKA_VALUE_LEN, CKA_SENSITIVE, and CKA_EXTRACTABLE based on the base
    /// master secret key.
    fn verify_key_expansion_template<'a>(
        &'a self,
        key: &Object,
        template: &'a [CK_ATTRIBUTE],
    ) -> Result<CkAttrs<'a>> {
        /* augment template, then check that it has all the right values */
        let is_sensitive = key.is_sensitive();
        let is_extractable = key.is_extractable();
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
        tmpl.add_missing_ulong(CKA_VALUE_LEN, &self.keylen);
        tmpl.add_missing_bool(CKA_ENCRYPT, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DECRYPT, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DERIVE, &CK_TRUE);
        if is_sensitive {
            tmpl.add_missing_bool(CKA_SENSITIVE, &CK_TRUE);
        } else {
            tmpl.add_missing_bool(CKA_SENSITIVE, &CK_FALSE);
        }
        if is_extractable {
            tmpl.add_missing_bool(CKA_EXTRACTABLE, &CK_TRUE);
        } else {
            tmpl.add_missing_bool(CKA_EXTRACTABLE, &CK_FALSE);
        }

        for attr in tmpl.as_slice() {
            match attr.type_ {
                CKA_VALUE_LEN => {
                    let val = attr.to_ulong()?;
                    if val != self.keylen {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKA_SENSITIVE => {
                    let val = attr.to_bool()?;
                    if val != is_sensitive {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKA_EXTRACTABLE => {
                    let val = attr.to_bool()?;
                    if val != is_extractable {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                _ => (),
            }
        }
        Ok(tmpl)
    }

    /// Performs the derivation for `CKM_TLS12_KEY_AND_MAC_DERIVE` /
    /// `CKM_TLS12_KEY_SAFE_DERIVE`
    ///
    /// Verifies the base key and template for the encryption key.
    ///
    /// Calls the TLS PRF with the "key expansion" label and combined
    /// randoms to generate a block of key material.
    ///
    /// Parses this block to extract client/server MAC keys and write keys,
    /// creating new key objects for them.
    ///
    /// If IVs are required, extracts and copies them into the
    /// `CK_SSL3_KEY_MAT_OUT` structure provided in the mechanism parameters.
    fn derive_mac_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let key_tmpl = self.verify_key_expansion_template(key, template)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_prf_seed(false);
        let dkmlen = (2 * (self.maclen + self.keylen + self.ivlen)) as usize;
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

        let mut keys = Vec::<Object>::with_capacity(4);
        let mut i = 0;

        if self.maclen > 0 {
            let maclen = self.maclen as usize;
            let is_sensitive = as_ck_bbool!(key, CKA_SENSITIVE, Some(true));
            let is_extractable =
                as_ck_bbool!(key, CKA_EXTRACTABLE, Some(false));
            let mut mac_tmpl = CkAttrs::with_capacity(6);
            mac_tmpl.add_ulong(CKA_CLASS, &CKO_SECRET_KEY);
            mac_tmpl.add_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
            mac_tmpl.add_bool(CKA_SIGN, &CK_TRUE);
            mac_tmpl.add_bool(CKA_VERIFY, &CK_TRUE);
            mac_tmpl.add_bool(CKA_SENSITIVE, &is_sensitive);
            mac_tmpl.add_bool(CKA_EXTRACTABLE, &is_extractable);

            let factory = objfactories
                .get_obj_factory_from_key_template(mac_tmpl.as_slice())?;
            let mut climac =
                factory.default_object_derive(mac_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut climac, dkm[i..(i + maclen)].to_vec())?;

            i += maclen;
            keys.push(climac);
            let mut srvmac =
                factory.default_object_derive(mac_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut srvmac, dkm[i..(i + maclen)].to_vec())?;
            i += maclen;
            keys.push(srvmac);
        }

        if self.keylen > 0 {
            let keylen = self.keylen as usize;
            let factory = objfactories
                .get_obj_factory_from_key_template(key_tmpl.as_slice())?;
            let mut clikey =
                factory.default_object_derive(key_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut clikey, dkm[i..(i + keylen)].to_vec())?;

            i += keylen;
            keys.push(clikey);
            let mut srvkey =
                factory.default_object_derive(key_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut srvkey, dkm[i..(i + keylen)].to_vec())?;
            i += keylen;
            keys.push(srvkey);
        }

        if self.ivlen > 0 {
            let ivlen = self.ivlen as usize;
            let mat_out = match self.mat_out {
                Some(mo) => mo,
                None => return Err(CKR_GENERAL_ERROR)?,
            };
            let cliiv = unsafe {
                core::slice::from_raw_parts_mut((*mat_out).pIVClient, ivlen)
            };
            cliiv.copy_from_slice(&dkm[i..(i + ivlen)]);
            i += ivlen;
            let srviv = unsafe {
                core::slice::from_raw_parts_mut((*mat_out).pIVServer, ivlen)
            };
            srviv.copy_from_slice(&dkm[i..(i + ivlen)]);
        }

        Ok(keys)
    }

    /// Performs the derivation for `CKM_TLS_KDF`
    ///
    /// Note: `CKM_TLS12_KDF` is considered just an alias of `CKM_TLS_KDF` and
    /// is deprecated as of PKCS#11 v3.2
    fn derive_generic_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);

        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;
        let dkmlen = match dkey.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_prf_seed(true);
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

        factory.as_secret_key_factory()?.set_key(&mut dkey, dkm)?;
        Ok(vec![dkey])
    }
}

impl MechOperation for TLSKDFOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Derive for TLSKDFOperation {
    /// Performs the appropriate TLS KDF derivation based on the mechanism used
    ///
    /// Dispatches to internal methods like `derive_master_key`,
    /// `derive_mac_key`, etc.
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        match self.mech {
            #[cfg(feature = "pkcs11_3_2")]
            CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE
            | CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH => {
                self.derive_master_key(key, template, mechanisms, objfactories)
            }
            CKM_TLS12_MASTER_KEY_DERIVE | CKM_TLS12_MASTER_KEY_DERIVE_DH => {
                self.derive_master_key(key, template, mechanisms, objfactories)
            }
            CKM_TLS12_KEY_AND_MAC_DERIVE | CKM_TLS12_KEY_SAFE_DERIVE => {
                self.derive_mac_key(key, template, mechanisms, objfactories)
            }
            CKM_TLS12_KDF | CKM_TLS_KDF => {
                self.derive_generic_key(key, template, mechanisms, objfactories)
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

/// Static collection of registered HMAC mechanisms for internal TLS MAC use
static MAC_MECHANISMS: Lazy<Mechanisms> = Lazy::new(|| {
    let mut mechanisms = Mechanisms::new();
    register_mechs_only(&mut mechanisms);
    mechanisms
});

/// Represents a TLS MAC operation
///
/// Used for mechanisms like `CKM_TLS_MAC` and `CKM_TLS12_MAC` (typically for
/// calculating the MAC for TLS Finished messages).
#[derive(Debug)]
pub struct TLSMACOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    seed: Vec<u8>,
    tlsprf: TLSPRF,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl TLSMACOperation {
    /// Creates a new TLS MAC operation
    ///
    /// Parses `CK_TLS_MAC_PARAMS`, validates the PRF mechanism and label
    /// choice (server/client finished), initializes the internal TLS PRF,
    /// and stores parameters.
    pub fn new(mech: &CK_MECHANISM, key: &Object) -> Result<TLSMACOperation> {
        #[cfg(feature = "fips")]
        if TLS_PRF_SELFTEST.result != CKR_OK {
            return Err(TLS_PRF_SELFTEST.result)?;
        }

        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => (),
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }
        let params = cast_params!(mech, CK_TLS_MAC_PARAMS);
        let prf = match hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };
        let maclen = params.ulMacLength as usize;
        let label = match params.ulServerOrClient {
            1 => TLS_SERVER_FINISHED,
            2 => TLS_CLIENT_FINISHED,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        let mac = MAC_MECHANISMS.get(prf)?;

        Ok(TLSMACOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            outputlen: maclen,
            seed: label.to_vec(),
            tlsprf: TLSPRF::init(key, mac, prf)?,
            #[cfg(feature = "fips")]
            fips_approved: is_hmac_fips_approved(prf),
        })
    }

    /// Internal helper to check state before starting/updating
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Internal helper to update the data being MAC'd
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        self.seed.extend_from_slice(data);
        Ok(())
    }

    /// Internal helper to finalize the MAC calculation
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;
        if output.len() != self.outputlen {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let out = self.tlsprf.finish(&self.seed, self.outputlen)?;
        output.copy_from_slice(out.as_slice());

        Ok(())
    }
}

impl MechOperation for TLSMACOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Sign for TLSMACOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Verify for TLSMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}
