# Kryoptic for Users

## What is Kryoptic ?

Kryoptic is a PKCS#11 soft token written in Rust. It uses OpenSSL for cryptography and supports multiple storage backends, such as SQLite and NSS DB.

## Module Initialization

Kryoptic is built as a dynamic library (`libkryoptic_pkcs11.so`) that can be loaded by applications expecting a PKCS#11 module. 

Applications initialize the token via the `C_Initialize()` function. Kryoptic can process custom configurations passed through the reserved argument in `C_Initialize()`:
* **Config file path:** By passing a string like `kryoptic_conf=/path/to/config.toml`.
* **Legacy SQLite path:** By directly passing the path to an SQLite database file ending in `.sql` (e.g., `/path/to/database.sql`).
* **NSS config directory:** By passing an NSS-style argument string containing `configDir=...`.

If no arguments are provided, Kryoptic falls back to searching for a TOML configuration file in predefined locations (e.g. /home/user/.config/kryoptic/token.conf).

## Environment variables

### Build Environment Variables
* `CONFDIR`: The directory where to search the default configuration. Defaults to `/usr/local/etc` if not provided.
* `KRYOPTIC_OPENSSL_SOURCES`: Path where OpenSSL sources are unpacked, used to statically link OpenSSL instead of using the system's dynamic libraries.
* `OSSL_BINDGEN_CLANG_ARGS`: Additional arguments passed into bindgen.
* `KRYOPTIC_FIPS_VENDOR`, `KRYOPTIC_FIPS_VERSION`, `KRYOPTIC_FIPS_BUILD`: Specifies the name, version, and additional build information returned by the embedded OpenSSL FIPS provider (requires FIPS build).

### Runtime Environment Variables
* `KRYOPTIC_CONF`: The path to the Kryoptic configuration file. This has the highest precedence.
* `XDG_CONFIG_HOME`: Used as a fallback if `KRYOPTIC_CONF` is not set. Kryoptic will look for `${XDG_CONFIG_HOME}/kryoptic/token.conf`.
* `HOME`: Used as a fallback if `XDG_CONFIG_HOME` is not set. Kryoptic will look for `${HOME}/.config/kryoptic/token.conf`.
* `KRYOPTIC_EC_POINT_ENCODING`: Can be used to override the `ec_point_encoding` specified in the configuration file. Valid values are `BYTES` or `DER`. This is useful when multiple applications use the same configuration file but expect different behaviors.

## Configuration Options

Kryoptic is typically configured using a TOML file. The main structure consists of global options and a list of independent slots. Slots cannot share the same storage.

**Note:** When a token storage SQL file is provided as the configuration option, an internal configuration is automatically generated, and the first available slot is assigned.

**Note:** Multiple tokens can be loaded via repeated invocations of `C_Initialize` using custom arguments. While configurations passed this way are useful for testing environments, they should be avoided in production. A comprehensive configuration file should be provided instead, as conflicts between configurations provided on the fly will cause initialization errors.

### Global Options

* `ec_point_encoding`: Allows setting a global default encoding for `CKA_EC_POINT` attributes, useful for applications that expect DER encoded EC Points. Values can be `Bytes` or `Der` (Default: `Bytes`).

### Slot Options (`[[slots]]`)

Each slot represents an idealized hardware slot for cryptographic operations and storage. It is defined within a `[[slots]]` block.

* `slot`: (Integer) The slot number identifier.
* `description`: (String, optional) The slot's description. A default one is returned if not provided.
* `manufacturer`: (String, optional) The slot's manufacturer string. A default one is returned if not provided.
* `dbtype`: (String) The token type / storage implementation (e.g., `"sqlite"`, `"nssdb"`).
* `dbargs`: (String) Storage specific configuration options. For example, the path to the token's database.
* `mechanisms`: (Array of Strings, optional) List of allowed mechanisms. It can be an allow list (e.g., `["CKM_SHA256"]`) to expose only the explicitly mentioned mechanisms. It can also act as a deny list if the exact string `"DENY"` is the first element (e.g., `["DENY", "CKM_SHA256"]`). Using `"DENY"` in any position other than the first is an error.
* `fips_behavior`: (Table, optional) Tweaks for behavior in FIPS mode.
  * `keys_always_sensitive`: (Boolean) Changes the behavior of the token in the slot to always enforce keys to be private/sensitive. (For NSS DB, this typically defaults to true).

### Example Configuration

```toml
[ec_point_encoding]
encoding = "Bytes"

[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/var/lib/kryoptic/token.sql"
mechanisms = ["DENY", "CKM_SHA256"]

[[slots]]
slot = 2
dbtype = "nssdb"
dbargs = "configDir=/etc/pki/nssdb"
```

## Example Uses

### Using pkcs11-tool to initialize a new token

You can use OpenSC's `pkcs11-tool` to initialize a token and set its PIN. Make sure you specify the `kryoptic` library using the `--module` argument.

**Note:** The user and SO PINs do not need to be just numerical; any strong passphrase can be used.

```bash
# Initialize a token and set the SO PIN
pkcs11-tool --module /path/to/libkryoptic_pkcs11.so \
    --init-token \
    --label "MyToken" \
    --so-pin 123456

# Initialize the User PIN
pkcs11-tool --module /path/to/libkryoptic_pkcs11.so \
    --init-pin \
    --login --login-type so --so-pin 123456 \
    --pin 1234
```

### Using OpenSSL with pkcs11-provider

You can use `kryoptic` with `openssl` by utilizing the `pkcs11-provider` module. To do this, configure OpenSSL to load the `pkcs11` provider via its configuration file. 

Here is an example `openssl.cnf` snippet demonstrating how to configure the `pkcs11-provider` with `kryoptic`. We prioritize using an environment variable expansion within the OpenSSL configuration for defining the `kryoptic` module path for flexibility:

```ini
[...]

[provider_sect]
default = default_sect
base = base_sect
pkcs11 = pkcs11_sect

[base_sect]
activate = 1

[default_sect]
activate = 1

[pkcs11_sect]
module = pkcs11
pkcs11-module-path = /usr/lib/pkcs11/libkryoptic_pkcs11.so
activate = 1

[...]
```

Here is an example demonstrating how to configure the environment and use `openssl` to generate a key pair and sign a certificate, similarly to how it's tested in the `pkcs11-provider` setup scripts:

```bash
# Optionally point the OpenSSL configuration to the kryoptic module via the environment variable
export PKCS11_PROVIDER_MODULE=/path/to/libkryoptic_pkcs11.so

# If a custom config file is used point OpenSSL at it.
export OPENSSL_CONF=/path/to/openssl.cnf

# Generate a new EC key pair directly in the token
openssl genpkey -propquery "provider=pkcs11" \
    -algorithm EC \
    -pkeyopt "ec_paramgen_curve:prime256v1" \
    -pkeyopt "pkcs11_uri:pkcs11:token=MyToken;object=my-ec-key"

# Create a self-signed certificate using the key stored in the token.
# Note: The URI is passed directly to the -signkey argument.
openssl x509 -new \
    -subj "/O=My Organization/CN=My Cert/" \
    -days 365 \
    -out cert.crt \
    -signkey "pkcs11:token=MyToken;object=my-ec-key;type=private?pin-value=1234"
```
