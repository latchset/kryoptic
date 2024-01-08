#[cfg(feature = "fips")]
include! {"ossl/drbg.rs"}

#[cfg(not(feature = "fips"))]
include! {"ossl/drbg.rs"}
