# NAME

softhsm_migrate - migrate SoftHSM v2 tokens to a PKCS#11 module

# SYNOPSIS

**softhsm_migrate** \[**-m**|**--pkcs11-module** _MODULE_\] \[**-i**|**--pkcs11-initargs** _INITARGS_\] \[**-p**|**--pkcs11-pin** _PIN_\] \[**-s**|**--pkcs11-slot** _SLOT_\] **-q**|**--softhsm2-pin** _PIN_ _SOFTHSM2_TOKEN_

# DESCRIPTION

**softhsm_migrate** reads cryptographic objects (such as keys and certificates) from a SoftHSM v2 token directory and imports them into a target PKCS#11 module, such as Kryoptic. 

It reads the internal SoftHSM v2 `.object` files, uses the provided SoftHSM v2 token PIN to derive the decryption key, decrypts the token's private and secret keys, and creates equivalent objects in the target PKCS#11 token.

# OPTIONS

**-m**, **--pkcs11-module** _MODULE_
: Path to the target PKCS#11 module shared library.

**-i**, **--pkcs11-initargs** _INITARGS_
: Initialization arguments passed to the target PKCS#11 module.

**-p**, **--pkcs11-pin** _PIN_
: PIN used for logging into the target PKCS#11 token.

**-s**, **--pkcs11-slot** _SLOT_
: Target PKCS#11 slot number.

**-q**, **--softhsm2-pin** _PIN_
: User PIN of the SoftHSM v2 token. This is required to decrypt the token's private and secret keys.

_SOFTHSM2_TOKEN_
: Path to the SoftHSM v2 token directory (the directory containing the `token.object` file).

# EXIT STATUS

**0**
: Success. All objects were migrated successfully.

**1-253**
: The number of objects that failed to import.

**254 (0xFE)**
: Fatal error parsing the SoftHSM v2 token or deriving its decryption key.

**255 (0xFF)**
: Fatal error loading, initializing, or authenticating to the target PKCS#11 module.

# EXAMPLES

Migrate a SoftHSM v2 token to a Kryoptic token:

    softhsm_migrate \
        -m /usr/lib/libkryoptic_pkcs11.so \
        -i /etc/kryoptic/kryoptic.conf \
        -p target_pin \
        -q softhsm_pin \
        /var/lib/softhsm/tokens/9a19985a-9037-e9df-657d-9947f7ba2120

# SEE ALSO

**kryoptic**(7), **kryoptic.conf**(5)
