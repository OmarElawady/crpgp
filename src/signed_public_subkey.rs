// use crate::err::*;
// use libc::c_char;

// #[no_mangle]
// pub extern "C" fn signed_public_subkey_free(signed_public_subkey: *mut pgp::SignedPublicSubKey) -> c_char {
//     if signed_public_subkey.is_null() {
//         update_last_error(Box::new("signed public subkey can't be null".into()));
//         return -1;
//     }

//     unsafe {
//         Box::from_raw(signed_public_subkey);
//     }
//     0
// }
