# This file describe some of the test artifacts in this directory

## NSS Databases

The `nssdbdir` and `nssdbdir2` directories contain NSS Databases. The
first is a database captured before the introduction of the PKCS#11 3.2
specification and we still use in test to ensure we support older
databases as well properly handle upgrading them. The new database ensures
we can interoperate with files created by NSS tools with the new
additional PKCS#11 3.2 attributes.
