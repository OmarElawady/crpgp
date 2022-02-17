pub mod types;
// use pgp::SecretKeyParamsBuilder;
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

#[no_mangle]
pub extern "C" fn params_builder_new() -> *mut pgp::composed::key::SecretKeyParamsBuilder {
    let mut builder = pgp::composed::key::SecretKeyParamsBuilder::default();
    builder
        .key_type(KeyType::EdDSA)
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
pub extern "C" fn params_builder_free(builder: *mut pgp::composed::key::SecretKeyParamsBuilder)  {
    assert!(!builder.is_null());
    unsafe {
        Box::from_raw(builder);
    }
}

#[no_mangle]
pub extern "C" fn params_builder_primary_user_id(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder,
    primary_user_id: *mut c_char,
) {
    let cfg = unsafe {
        assert!(!builder.is_null());

        &mut *builder
    };

    let primary_user_id = unsafe {
        assert!(!primary_user_id.is_null());

        CStr::from_ptr(primary_user_id)
    };
    cfg.primary_user_id(primary_user_id.to_str().unwrap().into());
}

#[no_mangle]
pub extern "C" fn params_builder_build(
    builder: *mut pgp::composed::key::SecretKeyParamsBuilder
) -> *mut pgp::composed::key::SecretKeyParams {
    let builder = unsafe {
        assert!(!builder.is_null());

        &mut *builder
    };

    Box::into_raw(Box::new(builder.build().unwrap()))
}


#[no_mangle]
pub extern "C" fn params_generate_secret_key_and_free (
    params: Box<pgp::composed::key::SecretKeyParams>
) -> *mut pgp::SecretKey {
    let params = *params;
    Box::into_raw(Box::new(params.generate().unwrap()))
}

#[no_mangle]
pub extern "C" fn secret_key_sign_and_free(
    secret_key: Box<pgp::SecretKey>
) -> *mut pgp::SignedSecretKey {
    let secret_key: pgp::SecretKey = *secret_key;
    let passwd_fn = || String::new();
    let signed_secret_key = secret_key.sign(passwd_fn).expect("couldn't convert");
    Box::into_raw(Box::new(signed_secret_key))
}

#[no_mangle]
pub extern "C" fn signed_secret_key_public_key(
    signed_secret_key: *mut pgp::SignedSecretKey
) -> *mut pgp::PublicKey {
    let signed_secret_key = unsafe {
        assert!(!signed_secret_key.is_null());

        &*signed_secret_key
    };
    let _passwd_fn = || String::new();
    let public_key = signed_secret_key.public_key();
    Box::into_raw(
        Box::new(public_key)
    )
}


#[no_mangle]
pub extern "C" fn signed_secret_create_signature(
    signed_secret_key: *mut pgp::SignedSecretKey,
    data: *mut u8,
    len: size_t
) -> *mut pgp::Signature {
    let signed_secret_key = unsafe {
        assert!(!signed_secret_key.is_null());

        &*signed_secret_key
    };
    let data = unsafe {
        assert!(!data.is_null());
        slice::from_raw_parts(data, len)
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();
    let passwd_fn = || String::new();
    let signature = signed_secret_key.create_signature(passwd_fn, HashAlgorithm::SHA2_256, digest).expect("failed to create signature");
    let now = chrono::Utc::now();
    let signature = pgp::Signature::new(
        pgp::types::Version::Old,
        pgp::packet::SignatureVersion::V4,
        pgp::packet::SignatureType::Binary,
        signed_secret_key.algorithm(),
        HashAlgorithm::SHA2_256,
        [digest[0], digest[1]],
        signature,
        vec![
            pgp::packet::Subpacket::SignatureCreationTime(now),
            pgp::packet::Subpacket::Issuer(signed_secret_key.key_id()),
        ],
        vec![],
    );
    Box::into_raw(Box::new(signature))
}


#[no_mangle]
pub extern "C" fn signature_serialize(
    signature: *mut pgp::Signature,
    output_len: *mut size_t
) -> *mut u8 {
    let signature = unsafe {
        assert!(!signature.is_null());

        &*signature
    };
    let mut bytes = signature.to_bytes().unwrap();
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
    let signature_vec = unsafe{
        assert!(!signature_bytes.is_null());

        Vec::from_raw_parts(signature_bytes, len, len)
    };
    let signature = pgp::Signature::from_slice(pgp::types::Version::Old, signature_vec.as_slice()).expect("couldn't parse signature");
    Box::into_raw(Box::new(signature))
}

#[no_mangle]
pub extern "C" fn signature_free(
    signature: *mut pgp::Signature
) {
    assert!(!signature.is_null());
    unsafe {
        Box::from_raw(signature);
    }
}

#[no_mangle]
pub extern "C" fn public_key_verify(
    cfg_ptr: *mut pgp::PublicKey,
    data: *mut u8,
    data_len: size_t,
    signature: *mut pgp::Signature
) -> bool {

    let signature = unsafe {
        assert!(!signature.is_null());

        &*signature
    };
    let public_key = unsafe {
        assert!(!cfg_ptr.is_null());

        &*cfg_ptr
    };
    let data = unsafe {
        assert!(!data.is_null());
        slice::from_raw_parts(data, data_len)
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();

    // let signature = pgp::Signature::from_slice(pgp::types::Version::Old, signature_vec.as_slice()).unwrap();
    let raw_signature = signature.signature.clone();
    match public_key
        .verify_signature(HashAlgorithm::SHA2_256, digest, &raw_signature) {
            Ok(_) => true,
            Err(e) => {println!("{}", e); false} 
        }
}

#[no_mangle]
pub extern "C" fn public_key_free(
    public_key: *mut pgp::PublicKey
) {
    assert!(!public_key.is_null());
    unsafe {
        Box::from_raw(public_key);
    }
}
