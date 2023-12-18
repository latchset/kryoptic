// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
include!("fips/drbg.rs");

#[cfg(not(feature = "fips"))]
include!("hacl/drbg.rs");
