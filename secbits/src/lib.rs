mod bytes;
// mod err;
mod mem;

pub use bytes::{SecBytes, SecReadBytes, SecWriteBytes};

#[cfg(miri)]
mod mock {
    use libc::*;

    // Replace `mlock` with a no-op during Miri tests
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mlock(_addr: *const c_void, _len: size_t) -> c_int {
        0 // Return success
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn munlock(_addr: *const c_void, _len: size_t) -> c_int {
        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn madvise(_addr: *const c_void, _len: size_t, _advice: c_int) -> c_int {
        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn explicit_bzero(addr: *const c_void, len: size_t) {
        let ptr = addr as *mut u8;
        unsafe { ptr.write_bytes(0, len) };
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int {
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::bytes::*;

    #[test]
    fn test_basic() {
        let ori0 = b"0123456789";
        let mut d0: Vec<u8> = ori0.into();
        let mut sbs = SecBytes::new(&mut d0).unwrap();
        assert_eq!(&d0, &[0; 10]);

        assert_eq!(sbs.view().unwrap().as_slice(), ori0);

        let ori1 = b"abcdefg";
        let mut d1: Vec<u8> = ori1.into();
        sbs.append(&mut d1[0..3]).unwrap();
        let expected = [ori0, &ori1[..3]].concat();
        assert_eq!(sbs.view().unwrap().as_slice(), &expected);
        assert_eq!(&d1[..3], &[0; 3]);
        assert_eq!(&d1[3..], b"defg");

        sbs.edit().unwrap().as_slice()[..3].copy_from_slice(b"xyz");
        let expected = [b"xyz", &ori0[3..], &ori1[..3]].concat();
        assert_eq!(sbs.view().unwrap().as_slice(), &expected);
    }
}
