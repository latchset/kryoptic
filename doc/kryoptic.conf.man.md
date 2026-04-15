% KRYOPTIC.CONF(5)
% 
% 

# NAME

kryoptic.conf - Configuration file for the Kryoptic PKCS#11 module

# SYNOPSIS

**/etc/kryoptic/token.conf**

**${XDG_CONFIG_HOME}/kryoptic/token.conf**

**${HOME}/.config/kryoptic/token.conf**

# DESCRIPTION

The **kryoptic.conf** file is a TOML-formatted configuration file used by the Kryoptic PKCS#11 module. It allows configuring global settings and provisioning multiple independent slots, each representing an idealized hardware slot where a cryptographic token can be utilized.

Kryoptic searches for the configuration file in the following order:

1. The path specified by the **KRYOPTIC_CONF** environment variable.
2. **${XDG_CONFIG_HOME}/kryoptic/token.conf** (if the **XDG_CONFIG_HOME** environment variable is set).
3. **${HOME}/.config/kryoptic/token.conf** (if the **HOME** environment variable is set).
4. A system-wide directory, typically **/usr/local/etc/kryoptic/token.conf** or **/etc/kryoptic/token.conf** depending on build-time configuration.

# GLOBAL OPTIONS

**[ec_point_encoding]**
:   Allows setting a global default encoding for `CKA_EC_POINT` attributes to maintain compatibility with applications that expect specific encodings (e.g., DER encoded EC Points).

    **encoding** = *string*
    :   Valid values are **"Bytes"** or **"Der"**. The default is **"Bytes"**.
        This can be overridden at runtime by setting the **KRYOPTIC_EC_POINT_ENCODING** environment variable.

# SLOT CONFIGURATION

Tokens are configured by defining one or more `[[slots]]` sections. In Kryoptic, slots provide independent tokens with their own separate storage. Slots cannot share the same storage.

**[[slots]]**

**slot** = *integer*
:   *(Required)* The slot number (a 32-bit unsigned integer) identifying this slot.

**description** = *string*
:   *(Optional)* A customized description for the slot. If not provided, a default description is returned to PKCS#11 applications.

**manufacturer** = *string*
:   *(Optional)* A customized manufacturer string. If not provided, a default string is used.

**dbtype** = *string*
:   *(Required)* The storage implementation (token type) for the slot (e.g., **"sqlite"**, **"nssdb"**).

**dbargs** = *string*
:   *(Required)* Storage-specific configuration options. For example, the path to a SQLite database file (e.g., `"/var/lib/kryoptic/token.sql"`).

**mechanisms** = *array of strings*
:   *(Optional)* A list of allowed or denied mechanisms, altering the mechanisms this token claims to implement.
    
    By default, this acts as an *allow list* (e.g., `["CKM_SHA256", "CKM_RSA_PKCS"]`), making only the explicitly mentioned mechanisms available.
    
    To configure a *deny list*, the first element must be the exact string `"DENY"`, followed by the mechanisms to be removed (e.g., `["DENY", "CKM_SHA256"]`). Using `"DENY"` in any position other than the first is not supported and will cause an error.

**[slots.fips_behavior]**
:   *(Optional)* Add tweaks for behavior in FIPS mode.

    **keys_always_sensitive** = *boolean*
    :   Changes the behavior of the token in the slot to always enforce keys to be private/sensitive. The default is **false** (unless `dbtype` is `"nssdb"`, which defaults to **true**).

# ENVIRONMENT VARIABLES

**KRYOPTIC_CONF**
:   Specifies the exact path to the **kryoptic.conf** file, bypassing default search paths. It is strongly advised to set this variable for most use cases.

**KRYOPTIC_EC_POINT_ENCODING**
:   Overrides the `ec_point_encoding.encoding` setting specified in the configuration file. Valid values are **"BYTES"** or **"DER"**.

# EXAMPLES

Below is an example of a **kryoptic.conf** file configuring two slots and specifying EC point encoding:

```toml
[ec_point_encoding]
encoding = "Der"

[[slots]]
slot = 1
description = "My SQLite Token"
manufacturer = "Kryoptic"
dbtype = "sqlite"
dbargs = "/var/lib/kryoptic/token.sql"
mechanisms = ["DENY", "CKM_MD5"]

[[slots]]
slot = 2
dbtype = "nssdb"
dbargs = "configDir=/etc/pki/nssdb"
```

# SEE ALSO

**kryoptic**(7), **softhsm_migrate**(1)
