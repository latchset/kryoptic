# NAME

kryoptic_otp - manage OTP tokens and generate HOTP/TOTP codes using Kryoptic PKCS#11

# SYNOPSIS

**kryoptic_otp** \[**-m** _MODULE_\] \[**-d** _DB_PATH_\] \[**-p** _PIN_\] \[**-n** _NAME_\]

**kryoptic_otp** **-N** **-n** _NAME_ \[**-m** _MODULE_\] \[**-d** _DB_PATH_\] \[**-t** _TYPE_\] \[**-s** _LEVEL_\] \[**-p** _PIN_ | **--no-pin**\] \[**--digits** _DIGITS_\] \[**--issuer** _ISSUER_\] \[**--account** _ACCOUNT_\] \[**-f** _FORMAT_\]

# DESCRIPTION

**kryoptic_otp** is a tool to manage HMAC-based One-Time Password (HOTP, RFC 4226) and Time-based One-Time Password (TOTP, RFC 6238) tokens using a PKCS#11 module (such as Kryoptic).

It can create and initialize new OTP tokens backed by a PKCS#11 SQLite database, provision secrets with configurable security parameters, export secrets and `otpauth://` URIs, and generate one-time passwords for authentication.

# MODES OF OPERATION

**Token Creation** (**-N**, **--new-otp**)
:   Provisions a new OTP key on the token. Requires **-n** (**--otp-name**). If the PKCS#11 token database is not yet initialized, it initializes the token and sets the user/SO PIN.

**Code Generation** (default)
:   Generates the current OTP code. For TOTP tokens, the code is computed based on the current system time and a hardcoded 30-second time step period. For HOTP tokens, the token counter is incremented after generation. If more than one OTP key is present on the token, **-n** (**--otp-name**) must be provided.

# OPTIONS

**-m**, **--module** _MODULE_
:   Path to the Kryoptic PKCS#11 shared library (`libkryoptic_pkcs11.so`). If not specified, standard library locations and the **KRYOPTIC** environment variable are searched.

**-d**, **--db-path** _DB_PATH_
:   Path to the Kryoptic database file. Defaults to `~/.kryoptic_otp/token.sql`.

**-N**, **--new-otp**
:   Creates a new OTP key instance. Requires **-n** (**--otp-name**).

**-n**, **--otp-name** _NAME_
:   Name of the OTP instance. When creating a new OTP, this assigns the key name. When generating a code from a database containing multiple OTP keys, this selects which key to use.

**-t**, **--otp-type** _TYPE_
:   OTP algorithm type: **totp** (default) or **hotp**. Case-insensitive.

**-p**, **--pin** _PIN_
:   User/SO PIN. If not provided via command line or the **KRYOPTIC_OTP_PIN** environment variable, the user will be prompted interactively with terminal echo disabled.

**--no-pin**
:   Creates the token without a PIN (sets PIN to "NOPIN"). This option is only permitted during initial token creation (**-N**) and conflicts with **-p** (**--pin**).

**-s**, **--security-level** _LEVEL_
:   Security level determining the HMAC digest algorithm and key size:
    * **low**: SHA-1 with a 20-byte (160-bit) seed. A warning is displayed as SHA-1 is weak and should not be used for new tokens if possible.
    * **normal** (default): SHA-256 with a 32-byte (256-bit) seed.
    * **high**: SHA-512 with a 64-byte (512-bit) seed.

**--digits** _DIGITS_
:   Number of digits in the generated OTP code: **6**, **7**, or **8**. Default is **6**.

**--issuer** _ISSUER_
:   Issuer name included in the generated `otpauth://` URI (e.g., "MyOrg").

**--account** _ACCOUNT_
:   Account identifier included in the generated `otpauth://` URI. Defaults to the OTP name.

**-f**, **--format** _FORMAT_
:   Output format when creating a new OTP token (**-N**):
    * **all** (default): Detailed summary including name, type, algorithm, digits, period (30s), issuer, account, base32 secret, hexadecimal secret, and `otpauth://` URI.
    * **base32**: Base32-encoded secret only.
    * **hex**: Hexadecimal-encoded secret only.
    * **uri**: `otpauth://` URI only.

# ENVIRONMENT VARIABLES

**KRYOPTIC**
:   Directory containing the Kryoptic PKCS#11 shared library (`libkryoptic_pkcs11.so`).

**KRYOPTIC_OTP_PIN**
:   PIN used for token authentication, avoiding interactive prompts.

**HOME**
:   Used to determine the default database path (`${HOME}/.kryoptic_otp/token.sql`).

# EXIT STATUS

**0**
:   Success.

**1**
:   Failure (e.g., invalid arguments, key not found, database error, or PKCS#11 failure).

# EXAMPLES

Create a new default TOTP token:

    kryoptic_otp -N -n myaccount

Create a new HOTP token with 8 digits and High security (SHA-512):

    kryoptic_otp -N -n myaccount -t hotp -s high --digits 8

Create a new TOTP token outputting only the `otpauth://` URI (e.g., to pipe to `qrencode`):

    kryoptic_otp -N -n myaccount --issuer "ExampleCorp" -f uri

Generate an OTP code from a database with a single key:

    kryoptic_otp

Generate an OTP code specifying the key name:

    kryoptic_otp -n myaccount

# SEE ALSO

**kryoptic**(7), **kryoptic.conf**(5), **softhsm_migrate**(1)
