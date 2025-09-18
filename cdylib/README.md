# Kryoptic PKCS#11 Module

This crate provides the shared library (`.so`, `.dylib`, `.dll`)
implementation of the Kryoptic PKCS#11 soft-token.

It exposes the standard `C_GetFunctionList`, `C_GetInterface` and
`C_GetInterfaceList` entry points for applications that consume PKCS#11
modules.

The actual implementation of the token can be found in the main
`kryoptic-lib` crate.
