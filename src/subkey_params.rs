use crate::err::*;
use libc::c_char;

#[no_mangle]
pub extern "C" fn subkey_params_free(subkey_params: *mut pgp::composed::key::SubkeyParams) -> c_char {
    if subkey_params.is_null() {
        update_last_error(Box::new("subkey params can't be null".into()));
        return -1;
    }

    unsafe {
        Box::from_raw(subkey_params);
    }
    0
}
