pub mod types;
use pgp::types::SecretKeyTrait;
use libc::c_char;
use types::*;
use pgp;
use smallvec::*;
use core::ffi::c_void;

// don't deallocate me
// http://kmdouglass.github.io/posts/complex-data-types-and-the-rust-ffi/
// https://doc.rust-lang.org/std/boxed/struct.Box.html#method.into_raw
// TODO: revise
#[no_mangle]
pub extern "C" fn signature_config_builder_new() -> Box<SecretKeyParams> {
    Box::new(SecretKeyParams {
        key_type: KeyType::Rsa(2048),

    can_sign: true,
    can_create_certificates: false,
    can_encrypt: true,

    preferred_symmetric_algorithms: SymmetricKeyAlgorithm::AES256,
    preferred_hash_algorithms: HashAlgorithm::SHA2_256,
    preferred_compression_algorithms: CompressionAlgorithm::ZLIB,

    primary_user_id: std::ptr::null(),

    // user_ids: Vec::new(),
    // user_attributes: Vec::new(),
    // passphrase: None,
    packet_version: Version::New,
    version: KeyVersion::V2,
    // TODO: support expiration
    // expiration: Option<Duration>,

    // subkeys: Vec::new(),

    })
}

#[no_mangle]
pub extern "C" fn param_set_version(
    cfg_ptr: Option<Box<SecretKeyParams>>,
    version: KeyVersion,
) {
    if let Some(mut cfg) = cfg_ptr {
        cfg.version = version;
        Box::into_raw(cfg);
    }
}

#[no_mangle]
pub extern "C" fn param_set_primary_user_id(
    cfg_ptr: Option<Box<SecretKeyParams>>,
    primary_user_id: *const c_char,
) {
    if let Some(mut cfg) = cfg_ptr {
        cfg.primary_user_id = primary_user_id;
        Box::into_raw(cfg);
    }
}

#[no_mangle]
pub extern "C" fn generate_secret_key(
    cfg_ptr: Option<Box<SecretKeyParams>>
) -> Option<Box<SecretKey>> {
    match cfg_ptr {
        Some(cfg) => {
            let mut key_params = pgp::composed::key::SecretKeyParamsBuilder::default();
            key_params
                .key_type(cfg.key_type.as_lib())
                .can_create_certificates(false)
                .can_sign(true)
                .primary_user_id("Me <me@example.com>".into())
                .preferred_symmetric_algorithms(smallvec![
                    cfg.preferred_symmetric_algorithms.as_lib(),
                ])
                .preferred_hash_algorithms(smallvec![
                    cfg.preferred_hash_algorithms.as_lib(),
                ])
                .preferred_compression_algorithms(smallvec![
                    cfg.preferred_compression_algorithms.as_lib(),
                ]);
                let secret_key_params = key_params.build().expect("Must be able to create secret key params");
                let secret_key = secret_key_params.generate().expect("Failed to generate a plain key.");
                Box::into_raw(cfg);
                Some(Box::new(SecretKey{
                    internal: Box::into_raw(Box::new(secret_key)) as *mut c_void
                }))
        },
        None => {
            None
        }
    }
}


#[no_mangle]
pub extern "C" fn sign(
    cfg_ptr: Option<Box<SecretKey>>
) -> Option<Box<SignedSecretKey>> {
    match cfg_ptr {
        Some(cfg) => {
            let passwd_fn = || String::new();
            let secret_key = unsafe { &mut *(cfg.internal as *mut pgp::composed::key::SecretKey) };
            let signed_secret_key = unsafe { Box::from_raw(secret_key) }.sign(passwd_fn).expect("couldn't convert");
            Some(
                Box::new(
                    SignedSecretKey{
                        internal: Box::into_raw(Box::new(signed_secret_key)) as *mut c_void,
                    }
                )
            )
        },
        None => {
            None
        }
    }
}

#[no_mangle]
pub extern "C" fn public_key(
    cfg_ptr: Option<Box<SignedSecretKey>>
) -> Option<Box<PublicKey>> {
    match cfg_ptr {
        Some(cfg) => {
            let _passwd_fn = || String::new();
            let signed_secret_key = unsafe { &mut *(cfg.internal as *mut pgp::composed::signed_key::secret::SignedSecretKey) };
            let public_key = signed_secret_key.public_key();
            Some(
                Box::new(
                    PublicKey{
                        internal: Box::into_raw(Box::new(public_key)) as *mut c_void,
                    }
                )
            )
        },
        None => {
            None
        }
    }
}