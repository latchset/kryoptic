// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use core::fmt::Debug;

use super::interface;

pub trait Object {
    fn get_handle(&self) -> interface::CK_OBJECT_HANDLE;
}

macro_rules! object_constructor {
    ($name:ty) => {
        impl Object for $name {
            fn get_handle(&self) -> interface::CK_OBJECT_HANDLE {
                self.handle
            }
        }
    }
}

impl Debug for dyn Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Something!")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyObject {
    handle: interface::CK_OBJECT_HANDLE,
    class: interface::CK_OBJECT_CLASS,
}

object_constructor!(KeyObject);

