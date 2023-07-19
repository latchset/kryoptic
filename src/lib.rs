#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod interface {
    #![allow(dead_code)]
    include!("pkcs11_bindings.rs");
}

use interface::{CK_FUNCTION_LIST_PTR_PTR, CK_RV};

#[no_mangle]
pub extern "C" fn C_GetFunctionList(_ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    0
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let list :CK_FUNCTION_LIST_PTR_PTR = std::ptr::null_mut();
        let result = C_GetFunctionList(list);
        assert_eq!(result, 0);
    }
}
