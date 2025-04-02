#define OSSL_CRYPTO_ALLOC __attribute__((__malloc__))
#define FIPS_MODULE 1

#include "ossl.h"
#include "crypto/evp.h"
#include "openssl/fips_names.h"
#include "internal/provider.h"
#include "internal/property.h"
#include "../crypto/evp/evp_local.h"
#include "../providers/common/include/prov/providercommon.h"
#include "../providers/common/include/prov/provider_ctx.h"
#include "openssl/self_test.h"
#include "openssl/indicator.h"

int OSSL_provider_init_int(const OSSL_CORE_HANDLE *handle,
                           const OSSL_DISPATCH *in,
                           const OSSL_DISPATCH **out,
                           void **provctx);
