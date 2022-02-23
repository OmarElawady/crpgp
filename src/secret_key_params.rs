use crate::err::*;
use std::ptr;

// TODO: is there a way to make this method not free its obj?
//       - or it will be hidden into a builder generate method?
#[no_mangle]
pub extern "C" fn params_generate_secret_key_and_free(
    params: Box<pgp::composed::key::SecretKeyParams>,
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
