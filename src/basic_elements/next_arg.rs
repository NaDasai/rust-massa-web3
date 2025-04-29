use anyhow::{Result, bail};

use crate::types::ArrayType;

use super::args::Args;

// --- Helper Trait for Generic `next_array` (Example) ---
// This allows `next_array` to call the correct `next_` method.
// You'd need to implement this for Args for each type T you want to support.
pub trait NextArg<T> {
    fn next_arg(&mut self, element_type: ArrayType) -> Result<T>;
}

// Example implementation for u32
impl NextArg<u32> for Args {
    fn next_arg(&mut self, element_type: ArrayType) -> Result<u32> {
        if element_type == ArrayType::U32 {
            self.next_u32()
        } else {
            bail!(
                "Type mismatch: Expected {:?}, but got request for u32",
                element_type
            );
        }
    }
}

impl NextArg<String> for Args {
    fn next_arg(&mut self, element_type: ArrayType) -> Result<String> {
        if element_type == ArrayType::String {
            self.next_string()
        } else {
            bail!(
                "Type mismatch: Expected {:?}, but got request for String",
                element_type
            );
        }
    }
}


impl NextArg<bool> for Args {
    fn next_arg(&mut self, element_type: ArrayType) -> Result<bool> {
        if element_type == ArrayType::Bool {
            self.next_bool()
        } else {
            bail!(
                "Type mismatch: Expected {:?}, but got request for bool",
                element_type
            );
        }
    }
}

