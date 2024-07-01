// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

/* misc utilities that do not really belong in any module */

#[macro_export]
macro_rules! bytes_to_vec {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *const u8;
        let size = $len as usize;
        if ptr == std::ptr::null_mut() || size == 0 {
            Vec::new()
        } else {
            let mut v = Vec::<u8>::with_capacity(size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, v.as_mut_ptr(), size);
                v.set_len(size);
            }
            v
        }
    }};
}

#[macro_export]
macro_rules! void_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_VOID_PTR
    };
}

#[macro_export]
macro_rules! byte_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_BYTE_PTR
    };
}
