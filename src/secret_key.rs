use crate::err::*;
use libc::c_char;
use std::ptr;

#[no_mangle]
pub extern "C" fn secret_key_sign(secret_key: *mut pgp::SecretKey) -> *mut pgp::SignedSecretKey {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return ptr::null_mut();
    }
    let secret_key = unsafe { &*secret_key };
    let passwd_fn = || String::new();
    let signed_secret_key = secret_key.clone().sign(passwd_fn);
    match signed_secret_key {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn secret_key_free(secret_key: *mut pgp::SecretKey) -> c_char {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return -1;
    }

    unsafe {
        Box::from_raw(secret_key);
    }
    0
}
