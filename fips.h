#define OSSL_CRYPTO_ALLOC __attribute__((__malloc__))
#define FIPS_MODULE 1

#include "ossl.h"
#include "openssl/fips_names.h"
#include "internal/provider.h"
#include "internal/property.h"
#include "../crypto/evp/evp_local.h"

OSSL_LIB_CTX *ossl_prov_ctx_get0_libctx(OSSL_PROVIDER *ctx);
int OSSL_provider_init_int(const OSSL_CORE_HANDLE *handle,
                           const OSSL_DISPATCH *in,
                           const OSSL_DISPATCH **out,
                           void **provctx);
