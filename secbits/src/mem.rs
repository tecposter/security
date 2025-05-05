use std::{alloc::Layout, ptr::NonNull, sync::LazyLock};

static PAGESIZE: LazyLock<usize> =
    LazyLock::new(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize);

enum ProtectionMode {
    None,
    Read,
    ReadWrite,
}

/// Secure memory region locked in RAM, automatically zeroed and unlocked on drop
pub struct SecMem {
    ptr: NonNull<u8>,
    cap: usize,
    layout: Layout,
}

impl SecMem {
    /// Creates new secure memory region with at least the requested size.
    /// Memory will be page-aligned and locked in RAM.
    pub fn new(required_size: usize) -> Result<Self, std::io::Error> {
        let pagesize = *PAGESIZE;

        // Safe page size calculation with overflow checks
        let sum = required_size
            .max(1)
            .checked_add(pagesize - 1)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Size overflow during alignment",
                )
            })?;
        let aligned_size = (sum / pagesize).checked_mul(pagesize).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Size overflow")
        })?;

        let layout = Layout::from_size_align(aligned_size, pagesize).map_err(|e| {
            log::error!("Failed to create layout: size={aligned_size}, align={pagesize}");
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;

        let raw_ptr = unsafe { std::alloc::alloc(layout) };
        let non_null = NonNull::new(raw_ptr).ok_or_else(|| {
            log::error!("failed to create non-null pointer");
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Allocation failed")
        })?;

        // Lock memory and prevent core dumps
        if let Err(e) = lock_memory(raw_ptr, aligned_size) {
            unsafe { std::alloc::dealloc(raw_ptr, layout) };
            return Err(e);
        }

        let res = Self {
            ptr: non_null,
            cap: aligned_size,
            layout,
        };
        res.set_noaccess()?;

        Ok(res)
    }

    /// Returns actual allocated capacity
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Returns a mutable pointer to the allocated memory
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Set memory to read-only mode
    pub fn set_readonly(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::Read)
    }

    /// Set memory to read-write mode
    pub fn set_readwrite(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::ReadWrite)
    }

    /// Set memory to no-access mode
    pub fn set_noaccess(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::None)
    }

    fn set_protection(&self, prot: ProtectionMode) -> Result<(), std::io::Error> {
        // Linux, macOS, FreeBSD, Android
        #[cfg(unix)]
        {
            let flags = match prot {
                ProtectionMode::None => libc::PROT_NONE,
                ProtectionMode::Read => libc::PROT_READ,
                ProtectionMode::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            };
            unsafe {
                if libc::mprotect(self.as_mut_ptr() as *mut libc::c_void, self.cap, flags) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }
}

impl Drop for SecMem {
    fn drop(&mut self) {
        if let Err(e) = self.set_readwrite() {
            log::error!(
                "CRITICAL ERROR: Failed to set read-write before drop: {e:?}. Aborting to prevent crash!"
            );
            std::process::abort();
        }

        // Securely erase memory before release
        zero_out(self.ptr, self.cap);

        if let Err(e) = unlock_memory(self.as_mut_ptr(), self.cap) {
            log::error!("Failed to unlock memory: {e:?}");
        }

        unsafe { std::alloc::dealloc(self.as_mut_ptr(), self.layout) }
    }
}

/// Securely zero memory using platform-specific intrinsics
pub fn zero_out(ptr: NonNull<u8>, len: usize) {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    unsafe {
        libc::explicit_bzero(ptr.as_ptr() as *mut libc::c_void, len)
    }

    #[cfg(target_os = "windows")]
    unsafe {
        use winapi::um::memoryapi::SecureZeroMemory;
        SecureZeroMemory(ptr.as_ptr() as *mut winapi::ctypes::c_void, len);
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
    {
        let mut addr = ptr.as_ptr();
        let end = unsafe { addr.add(len) };
        while addr < end {
            unsafe {
                addr.write_volatile(0);
                addr = addr.add(1);
            }
        }
        // Prevent compiler from optimizing out the zeroing
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// Memory locking
fn lock_memory(ptr: *mut u8, len: usize) -> Result<(), std::io::Error> {
    unsafe {
        let addr = ptr as *mut libc::c_void;

        #[cfg(target_os = "linux")]
        if libc::madvise(addr, len, libc::MADV_WIPEONFORK) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        let madvise_flag = libc::MADV_DONTDUMP;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        let madvise_flag = libc::MADV_NOCORE;

        if libc::madvise(addr, len, madvise_flag) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        if libc::mlock(addr, len) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

fn unlock_memory(ptr: *mut u8, len: usize) -> Result<(), std::io::Error> {
    unsafe {
        let addr = ptr as *mut libc::c_void;

        #[cfg(target_os = "linux")]
        if libc::madvise(addr, len, libc::MADV_KEEPONFORK) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        let madvise_flag = libc::MADV_DODUMP;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        let madvise_flag = libc::MADV_CORE;

        if libc::madvise(addr, len, madvise_flag) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        if libc::munlock(addr, len) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
