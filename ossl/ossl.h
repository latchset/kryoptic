#ifdef _KRYOPTIC_FIPS_
#define OSSL_CRYPTO_ALLOC __attribute__((__malloc__))
#define FIPS_MODULE 1
#endif /* _KRYOPTIC_FIPS_ */

#define OPENSSL_NO_DEPRECATED_3_0

#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/kdf.h"
#include "openssl/err.h"
#include "openssl/provider.h"

#ifdef _KRYOPTIC_FIPS_
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
#endif /* _KRYOPTIC_FIPS_ */
