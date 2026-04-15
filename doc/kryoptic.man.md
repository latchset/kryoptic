% KRYOPTIC(7)
% 
% 

# NAME

kryoptic - A PKCS#11 soft token written in Rust

# SYNOPSIS

**libkryoptic_pkcs11.so**

# DESCRIPTION

**Kryoptic** is a PKCS#11 software token implemented in Rust. It utilizes OpenSSL for cryptographic operations and provides support for multiple storage backends, including SQLite and NSS DB. It is distributed as a dynamic library (`libkryoptic_pkcs11.so`) that can be loaded by applications expecting a standard PKCS#11 module.

Kryoptic aims to provide a modern, secure, and flexible software token. It can be built to use the system OpenSSL dynamically or can be statically linked. It also includes support for FIPS 140-3 builds (when linked against OpenSSL's `libfips.a`), restricting algorithms and enforcing FIPS approved behaviors.

# INITIALIZATION

Applications initialize the Kryoptic token via the standard PKCS#11 `C_Initialize()` function. Kryoptic can process custom configurations passed through the reserved argument in `C_Initialize()`, allowing flexible initialization methods:

* **Config file path:** e.g., `kryoptic_conf=/path/to/config.toml`
* **Legacy SQLite path:** e.g., `/path/to/database.sql`
* **NSS config directory:** e.g., `configDir=/etc/pki/nssdb`

If no explicit arguments are provided, Kryoptic falls back to searching for its TOML configuration file in predefined system and user locations.

# ENVIRONMENT VARIABLES

Several environment variables affect the runtime behavior of Kryoptic:

**KRYOPTIC_CONF**
:   The path to the Kryoptic configuration file. This has the highest precedence.

**XDG_CONFIG_HOME**
:   Used as a fallback if **KRYOPTIC_CONF** is not set. Kryoptic will look for `${XDG_CONFIG_HOME}/kryoptic/token.conf`.

**HOME**
:   Used as a fallback if **XDG_CONFIG_HOME** is not set. Kryoptic will look for `${HOME}/.config/kryoptic/token.conf`.

**KRYOPTIC_EC_POINT_ENCODING**
:   Can be used to override the default `ec_point_encoding` specified in the configuration file. Valid values are **BYTES** or **DER**.

# SEE ALSO

**kryoptic.conf**(5), **softhsm_migrate**(1)
