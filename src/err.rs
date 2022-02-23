use libc::c_char;
use libc::c_int;
use std::cell::RefCell;
use std::ptr;
use std::slice;

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
