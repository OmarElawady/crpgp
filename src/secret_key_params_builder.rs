use crate::err::*;

use libc::c_char;

use pgp;
use crate::types::KeyType;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;

use pgp::types::CompressionAlgorithm;

use smallvec::*;
use std::ffi::CStr;
use std::ptr;

#[no_mangle]
pub extern "C" fn params_builder_new() -> *mut pgp::composed::key::SecretKeyParamsBuilder {
    let mut builder = pgp::composed::key::SecretKeyParamsBuilder::default();
    builder
        .can_create_certificates(false)
        .can_sign(true)
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256,])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB,]);
    Box::into_raw(Box::new(builder))
}

#[no_mangle]
pub extern "C" fn params_builder_primary_user_id(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
    primary_user_id: *mut c_char,
) -> c_char {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1;
    }
    if primary_user_id.is_null() {
        update_last_error(Box::new("primary user id can't be null".into()));
        return -1;
    }
    let cfg = unsafe { &mut *builder };

    let primary_user_id = unsafe { CStr::from_ptr(primary_user_id) };
    let primary_user_id = primary_user_id.to_str();
    match primary_user_id {
        Ok(v) => {
            cfg.primary_user_id(v.into());
        }
        Err(e) => {
            update_last_error(e.to_string());
        }
    };
    0
}

#[no_mangle]
pub extern "C" fn params_builder_key_type(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
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

// TODO: support adding multiple subkeys
#[no_mangle]
pub extern "C" fn params_builder_subkey(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
    subkey: *mut pgp::composed::key::SubkeyParams,
) -> c_char {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1;
    }
    if subkey.is_null() {
        update_last_error(Box::new("subkey can't be null".into()));
        return -1;
    }
    let builder = unsafe { &mut *builder };

    let subkey = unsafe { (&*subkey).clone() };
    builder.subkeys(vec![subkey]);
    0
}

#[no_mangle]
pub extern "C" fn params_builder_build(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
) -> *mut pgp::composed::key::SecretKeyParams {
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

#[no_mangle]
pub extern "C" fn params_builder_free(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
) -> c_char {
    println!("free builder");
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(builder);
    };
    return 0;
}
