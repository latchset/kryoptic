// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

// Currently only the json storga eis available.
// Later on will include others and a mechanism to chose which storage
// mechanism to actually use (at build time or run time).
include!("storage/json.rs");
