use crate::err::*;

use libc::c_char;

use pgp;
use crate::types::KeyType;
use std::ptr;

#[no_mangle]
pub extern "C" fn subkey_params_builder_new() -> *mut pgp::composed::key::SubkeyParamsBuilder {
    let mut builder = pgp::composed::key::SubkeyParamsBuilder::default();
    builder
        .can_encrypt(true);
    Box::into_raw(Box::new(builder))
}

#[no_mangle]
pub extern "C" fn subkey_params_builder_key_type(
    builder: *mut pgp::composed::key::SubkeyParamsBuilder,
    key_type: KeyType,
) -> c_char {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1;
    }
    let builder = unsafe {
        &mut *builder
    };
    builder.key_type(key_type.as_lib());
    return 0
}

#[no_mangle]
pub extern "C" fn subkey_params_builder_free(
    builder: *mut pgp::composed::key::SubkeyParamsBuilder,
) -> c_char {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(builder);
    };
    return 0;
}

#[no_mangle]
pub extern "C" fn subkey_params_builder_build(
    builder: *mut pgp::composed::key::SubkeyParamsBuilder,
) -> *mut pgp::composed::key::SubkeyParams {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return ptr::null_mut();
    }
    let builder = unsafe { &mut *builder };
    match builder.build() {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e);
            ptr::null_mut()
        }
    }
}
