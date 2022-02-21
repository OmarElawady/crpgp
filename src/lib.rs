pub mod types;
// use pgp::SecretKeyParamsBuilder;
use pgp::Deserializable;
use pgp::Message;
use libc::c_int;
use std::cell::RefCell;
use pgp::types::PublicKeyTrait;
use pgp::de::Deserialize;
use pgp::ser::Serialize;
use pgp::types::KeyTrait;
use libc::size_t;
use std::ffi::CStr;
use pgp::types::SecretKeyTrait;
use libc::c_char;
use pgp;
use pgp::crypto::hash::HashAlgorithm;
use std::slice;
use pgp::composed::KeyType;
use pgp::types::{CompressionAlgorithm};
use pgp::crypto::{sym::SymmetricKeyAlgorithm};
use smallvec::*;
use sha2::{Sha256, Digest};
use std::ptr;
use rand::rngs::OsRng;

thread_local!(
    static LAST_ERROR: RefCell<Option<Box<String>>> = RefCell::new(None);
);

/// Set the thread-local `LAST_ERROR` variable.
pub fn update_last_error<E: Into<Box<String>> + 'static>(e: E) {
    let boxed = e.into();

    LAST_ERROR.with(|last| {
        *last.borrow_mut() = Some(boxed);
    });
}

/// Get the last error, clearing the variable in the process.
pub fn get_last_error() -> Option<Box<String>> {
    LAST_ERROR.with(|last| last.borrow_mut().take())
}

#[no_mangle]
pub extern "C" fn last_error_length() -> c_int {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => err.to_string().len() as c_int + 1,
        None => 0,
    })
}

/// Write the latest error message to a buffer.
///
/// # Returns
///
/// This returns the number of bytes written to the buffer. If no bytes were
/// written (i.e. there is no last error) then it returns `0`. If the buffer
/// isn't big enough or a `null` pointer was passed in, you'll get a `-1`.
#[no_mangle]
pub unsafe extern "C" fn error_message(buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        return -1;
    }

    let buffer = slice::from_raw_parts_mut(buffer as *mut u8, length as usize);

    // Take the last error, if there isn't one then there's no error message to
    // display.
    let err = match get_last_error() {
        Some(e) => e,
        None => return 0,
    };

    let error_message = format!("{}", err);
    let bytes_required = error_message.len() + 1;

    if buffer.len() < bytes_required {
        // We don't have enough room. Make sure to return the error so it
        // isn't accidentally consumed
        update_last_error(err);
        return -1;
    }

    let data = error_message.as_bytes();
    ptr::copy_nonoverlapping(data.as_ptr(), buffer.as_mut_ptr(), data.len());

    // zero out the rest of the buffer just in case
    let rest = &mut buffer[data.len()..];
    ptr::write_bytes(rest.as_mut_ptr(), 0, rest.len());

    data.len() as c_int
}

fn vec_from_ptr<T: Clone>(bytes: *mut T, len: size_t) -> Vec<T> {
    unsafe {
        let v = Vec::from_raw_parts(bytes, len, len);
        let res = v.clone();
        std::mem::forget(v);
        res
    }
}

#[no_mangle]
pub extern "C" fn params_builder_new() -> *mut pgp::composed::key::SecretKeyParamsBuilder {
    let mut builder = pgp::composed::key::SecretKeyParamsBuilder::default();
    builder
        .key_type(KeyType::Rsa(2048))
        .can_create_certificates(false)
        .can_sign(true)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_256,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
        ]);
    Box::into_raw(Box::new(builder))
}

#[no_mangle]
pub extern "C" fn params_builder_free(builder: *mut pgp::composed::key::SecretKeyParamsBuilder) -> c_char {
    println!("free builder");
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1
    }
    unsafe {
        Box::from_raw(builder);
    };
    return 0
}

#[no_mangle]
pub extern "C" fn params_builder_primary_user_id(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
    primary_user_id: *mut c_char,
) -> c_char {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return -1
    }
    if primary_user_id.is_null() {
        update_last_error(Box::new("primary user id can't be null".into()));
        return -1
    }
    let cfg = unsafe {
        &mut *builder
    };

    let primary_user_id = unsafe {
        CStr::from_ptr(primary_user_id)
    };
    let primary_user_id = primary_user_id.to_str();
    match primary_user_id {
        Ok(v) => {cfg.primary_user_id(v.into());},
        Err(e) => {update_last_error(e.to_string());},
    };
    0
}

#[no_mangle]
pub extern "C" fn params_builder_build(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder
) -> *mut pgp::composed::key::SecretKeyParams {
    if builder.is_null() {
        update_last_error(Box::new("builder can't be null".into()));
        return ptr::null_mut()
    }
    let builder = unsafe {
        &mut *builder
    };
    match builder.build() {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e);
            ptr::null_mut()
        }
    }
}

// TODO: is there a way to make this method not free its obj?
//       - or it will be hidden into a builder generate method?
#[no_mangle]
pub extern "C" fn params_generate_secret_key_and_free (
    params: Box<pgp::composed::key::SecretKeyParams>
) -> *mut pgp::SecretKey {
    let params = *params;
    match params.generate() {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn secret_key_sign(
    secret_key: *mut pgp::SecretKey
) -> *mut pgp::SignedSecretKey {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return ptr::null_mut()
    }
    let secret_key = unsafe {
        &*secret_key
    };
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
pub extern "C" fn secret_key_free(
    secret_key: *mut pgp::SecretKey
) -> c_char {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return -1
    }

    unsafe {
        Box::from_raw(secret_key);
    }
    0
}

#[no_mangle]
pub extern "C" fn signed_secret_key_public_key(
    signed_secret_key: *mut pgp::SignedSecretKey
) -> *mut pgp::PublicKey {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut()
    }
    let signed_secret_key = unsafe {
        &*signed_secret_key
    };
    let public_key = signed_secret_key.public_key();
    Box::into_raw(
        Box::new(public_key)
    )
}


#[no_mangle]
pub extern "C" fn signed_secret_key_create_signature(
    signed_secret_key: *mut pgp::SignedSecretKey,
    data: *mut u8,
    len: size_t
) -> *mut pgp::Signature {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut()
    }
    if data.is_null() {
        update_last_error(Box::new("data can't be null".into()));
        return ptr::null_mut()
    }
    let signed_secret_key = unsafe {
        &*signed_secret_key
    };
    let data = unsafe {
        slice::from_raw_parts(data, len)
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();
    let passwd_fn = || String::new();
    let signature = signed_secret_key.create_signature(passwd_fn, HashAlgorithm::SHA2_256, digest);
    if let Err(e) = signature {
        update_last_error(e.to_string());
        return ptr::null_mut()
    }
    let now = chrono::Utc::now();
    let signature = pgp::Signature::new(
        pgp::types::Version::Old,
        pgp::packet::SignatureVersion::V4,
        pgp::packet::SignatureType::Binary,
        signed_secret_key.algorithm(),
        HashAlgorithm::SHA2_256,
        [digest[0], digest[1]],
        signature.unwrap(), // safe unwrap
        vec![
            pgp::packet::Subpacket::SignatureCreationTime(now),
            pgp::packet::Subpacket::Issuer(signed_secret_key.key_id()),
        ],
        vec![],
    );
    Box::into_raw(Box::new(signature))
}

#[no_mangle]
pub extern "C" fn signed_secret_key_decrypt(
    secret_key: *mut pgp::SignedSecretKey,
    encrypted: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return ptr::null_mut()
    }
    if encrypted.is_null() {
        update_last_error(Box::new("encrypted data can't be null".into()));
        return ptr::null_mut()
    }
    if len.is_null() {
        update_last_error(Box::new("length data can't be null".into()));
        return ptr::null_mut()
    }
    let secret_key = unsafe {
        &*secret_key
    };

    let data = vec_from_ptr(encrypted, unsafe{*len});
    let msg = Message::from_bytes(data.as_slice());
    if let Err(e) = msg {
        update_last_error(e.to_string());
        return ptr::null_mut()    
    }
    let msg = msg.unwrap(); // safe unwrap
    let msg = msg.decrypt(|| "".into(), || "".into(), &[secret_key][..]);
    if let Err(e) = msg {
        update_last_error(e.to_string());
        return ptr::null_mut()    
    }
    let mut msg = msg.unwrap(); // safe unwrap
    let decrypted = msg.0.next();
    if let None = decrypted {
        update_last_error(Box::new("message doesn't contain content".into()));
        return ptr::null_mut()
    }
    let decrypted = decrypted.unwrap(); // safe unwrap
    if let Err(e) = decrypted {
        update_last_error(e.to_string());
        return ptr::null_mut()    
    }
    let decrypted = decrypted.unwrap(); // safe unwrap
    let decompressed = decrypted.decompress();
    if let Err(e) = decompressed {
        update_last_error(e.to_string());
        return ptr::null_mut()        
    }
    let decompressed = decompressed.unwrap(); // safe unwrap
    let content = decompressed.get_content();
    if let Err(e) = content {
        update_last_error(e.to_string());
        return ptr::null_mut()        
    }
    if let Ok(None) = content {
        update_last_error(Box::new("Message content is None(?!)".into()));
        return ptr::null_mut()        
    }
    let content = content.unwrap(); // safe unwrap
    let mut content = content.unwrap(); // safe unwrap
    let res = content.as_mut_ptr();
    unsafe {
        *len = content.len();
    }
    std::mem::forget(content);
    res
}

#[no_mangle]
pub extern "C" fn signed_secret_key_free(
    signed_secret_key: *mut pgp::SignedSecretKey,
) -> c_char {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return -1
    }

    unsafe {
        Box::from_raw(signed_secret_key);
    }
    0
} 


#[no_mangle]
pub extern "C" fn signature_serialize(
    signature: *mut pgp::Signature,
    output_len: *mut size_t
) -> *mut u8 {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return ptr::null_mut()
    }
    let signature = unsafe {
        &*signature
    };
    let bytes = signature.to_bytes();
    if let Err(e) = bytes {
        update_last_error(e.to_string());
        return ptr::null_mut()
    }
    let mut bytes = bytes.unwrap(); // safe unwrap
    bytes.shrink_to_fit();
    unsafe {
        *output_len = bytes.len()
    }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

#[no_mangle]
pub extern "C" fn signature_deserialize(
    signature_bytes: *mut u8,
    len: size_t
) -> *mut pgp::Signature {
    if signature_bytes.is_null() {
        update_last_error(Box::new("signature bytes can't be null".into()));
        return ptr::null_mut()
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
pub extern "C" fn signature_free(
    signature: *mut pgp::Signature
) -> c_char {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1
    }
    unsafe {
        Box::from_raw(signature);
    }
    0
}

#[no_mangle]
pub extern "C" fn ptr_free(
    ptr: *mut u8
) -> c_char {
    if ptr.is_null() {
        update_last_error(Box::new("pointer can't be null".into()));
        return -1
    }
    unsafe {
        Box::from_raw(ptr);
    }
    0
}

#[no_mangle]
pub extern "C" fn public_key_verify(
    public_key: *mut pgp::PublicKey,
    data: *mut u8,
    data_len: size_t,
    signature: *mut pgp::Signature
) -> c_char {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return -1
    }
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1
    }

    let signature = unsafe {
        &*signature
    };
    let public_key = unsafe {
        &*public_key
    };
    let data = unsafe {
        slice::from_raw_parts(data, data_len)
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();

    let raw_signature = signature.signature.clone();
    match public_key
        .verify_signature(HashAlgorithm::SHA2_256, digest, &raw_signature) {
            Ok(_) => 0,
            Err(e) => {
                update_last_error(e.to_string());
                -1
            } 
        }
}

#[no_mangle]
pub extern "C" fn public_key_free(
    public_key: *mut pgp::PublicKey
) -> c_char {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return -1
    }

    unsafe {
        Box::from_raw(public_key);
    }
    0
}

#[no_mangle]
pub extern "C" fn public_key_encrypt(
    public_key: *mut pgp::PublicKey,
    data: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return ptr::null_mut()
    }
    if data.is_null() {
        update_last_error(Box::new("data can't be null".into()));
        return ptr::null_mut()
    }
    let public_key = unsafe {
        &*public_key
    };

    let data = vec_from_ptr(data, unsafe{*len});
    let msg = Message::new_literal_bytes("", data.as_slice());
    let compressed = msg.compress(CompressionAlgorithm::ZLIB);
    if let Err(e) = compressed {
        update_last_error(e.to_string());
        return ptr::null_mut()
    }
    let compressed = compressed.unwrap(); // safe unwrap
    let encrypted = compressed.encrypt_to_keys(&mut OsRng, SymmetricKeyAlgorithm::AES128, &[&public_key][..]);
    if let Err(e) = encrypted {
        update_last_error(e.to_string());
        return ptr::null_mut()
    }
    let encrypted = encrypted.unwrap(); // safe unwrap
    let bytes_vec = encrypted.to_bytes();    
    if let Err(e) = bytes_vec {
        update_last_error(e.to_string());
        return ptr::null_mut()
    }
    let mut bytes_vec = bytes_vec.unwrap();    
    let bytes_ptr = bytes_vec.as_mut_ptr(); // safe unwrap
    unsafe {
        *len = bytes_vec.len();
    }
    std::mem::forget(bytes_vec);
    return bytes_ptr
}
