use crate::err::*;
use crate::utils::*;

use libc::c_char;
use libc::size_t;
use pgp;

use pgp::de::Deserialize;
use pgp::ser::Serialize;

use std::ptr;

#[no_mangle]
pub extern "C" fn signature_serialize(
    signature: *mut pgp::Signature,
    output_len: *mut size_t,
) -> *mut u8 {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return ptr::null_mut();
    }
    let signature = unsafe { &*signature };
    let bytes = signature.to_bytes();
    if let Err(e) = bytes {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let mut bytes = bytes.unwrap(); // safe unwrap
    bytes.shrink_to_fit();
    unsafe { *output_len = bytes.len() }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

#[no_mangle]
pub extern "C" fn signature_deserialize(
    signature_bytes: *mut u8,
    len: size_t,
) -> *mut pgp::Signature {
    if signature_bytes.is_null() {
        update_last_error(Box::new("signature bytes can't be null".into()));
        return ptr::null_mut();
    }
    let signature_vec = vec_from_ptr(signature_bytes, len);
    let signature = pgp::Signature::from_slice(pgp::types::Version::Old, signature_vec.as_slice());
    match signature {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn signature_free(signature: *mut pgp::Signature) -> c_char {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(signature);
    }
    0
}
