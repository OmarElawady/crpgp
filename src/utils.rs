use crate::err::*;
use libc::{c_char, size_t};

pub fn vec_from_ptr<T: Clone>(bytes: *mut T, len: size_t) -> Vec<T> {
    unsafe {
        let v = Vec::from_raw_parts(bytes, len, len);
        let res = v.clone();
        std::mem::forget(v);
        res
    }
}
#[no_mangle]
pub extern "C" fn ptr_free(ptr: *mut u8) -> c_char {
    if ptr.is_null() {
        update_last_error(Box::new("pointer can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(ptr);
    }
    0
}
