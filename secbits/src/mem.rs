use std::{ptr::NonNull, sync::LazyLock};

static PAGESIZE: LazyLock<usize> = LazyLock::new(|| get_page_size());

// Memory Protection Key (MPK) constants - platform-specific protection flags
const PKEY_DISABLE_ACCESS: u32 = 0x1;
const PKEY_DISABLE_WRITE: u32 = 0x2;
// const PKEY_DISABLE_EXECUTE: u32 = 0x4;
const PKEY_ENABLE_ALL: u32 = 0;
// const PKEY_ENABLE_READONLY: u32 = PKEY_DISABLE_WRITE;

/// Memory protection modes mapped to OS-specific flags
#[derive(Debug)]
enum ProtectionMode {
    None,      // No access allowed
    Read,      // Read-only access
    ReadWrite, // Full read-write access
}

impl ProtectionMode {
    /// Convert to Linux protection flags (used with mprotect)
    fn to_linux_prot(&self) -> i32 {
        match self {
            ProtectionMode::None => libc::PROT_NONE,
            ProtectionMode::Read => libc::PROT_READ,
            ProtectionMode::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
        }
    }

    fn to_thread_rights(&self) -> u32 {
        match self {
            ProtectionMode::None => PKEY_DISABLE_ACCESS,
            ProtectionMode::Read => PKEY_DISABLE_WRITE,
            ProtectionMode::ReadWrite => PKEY_ENABLE_ALL,
        }
    }

    /// Convert to Windows protection flags
    #[cfg(target_os = "windows")]
    fn to_windows_prot(&self) -> winapi::shared::minwindef::DWORD {
        match self {
            ProtectionMode::None => winapi::um::winnt::PAGE_NOACCESS,
            ProtectionMode::Read => winapi::um::winnt::PAGE_READONLY,
            ProtectionMode::ReadWrite => winapi::um::winnt::PAGE_READWRITE,
        }
    }
}

/// Represents a securely allocated memory region
///
/// This structure manages a memory region with security hardening:
/// - Page-aligned allocation
/// - Automatic secure zeroing before release
/// - Memory locking to prevent swapping
/// - Fork wiping protection (Linux)
/// - Core dump exclusion
/// - Fine-grained access control
pub struct SecSpace {
    ptr: NonNull<u8>, // Non-null pointer to memory region
    cap: usize,       // Capacity in bytes (always page-aligned)
    pkey: Option<i32>,
}

impl SecSpace {
    /// Allocate secure memory space with the given capacity
    ///
    /// # Arguments
    /// * `cap` - Desired capacity in bytes
    ///
    /// # Security
    /// - Allocations are page-aligned
    /// - Memory is locked (mlock/VirtualLock)
    /// - Marked to wipe on fork (Linux)
    /// - Excluded from core dumps
    /// - Starts with no-access permissions
    pub fn with_capacity(cap: usize) -> std::io::Result<Self> {
        if cap == 0 {
            Ok(Self {
                ptr: NonNull::dangling(),
                cap: 0,
                pkey: None,
            })
        } else {
            check_alignment(cap)?;

            let ptr = sec_allocate(cap)?;
            wipe_on_fork(ptr, cap)
                .and_then(|_| dont_dump_core(ptr, cap))
                .and_then(|_| lock_memory(ptr, cap))
                .map_err(|e| {
                    sec_free(ptr, cap).ok();
                    e
                })?;

            let res = Self {
                ptr,
                cap,
                pkey: mpk_protect(ptr, cap, ProtectionMode::ReadWrite).ok(),
            };
            res.set_noaccess()?;

            Ok(res)
        }
    }

    /// Get allocated capacity
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Get mutable pointer to memory
    ///
    /// # Safety
    /// Caller must ensure proper access protection is set
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn set_readonly(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::Read)
    }

    pub fn set_readwrite(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::ReadWrite)
    }

    pub fn set_noaccess(&self) -> Result<(), std::io::Error> {
        self.set_protection(ProtectionMode::None)
    }

    fn set_protection(&self, prot: ProtectionMode) -> Result<(), std::io::Error> {
        if self.cap == 0 {
            return Ok(());
        }

        if let Some(pkey) = self.pkey {
            mpk_set(pkey, prot)?;
        } else {
            protect_memory(self.ptr, self.cap, prot)?;
        }
        Ok(())
    }
}

impl Drop for SecSpace {
    fn drop(&mut self) {
        if self.cap == 0 {
            return;
        }

        if let Err(e) = self
            .set_readwrite()
            .and_then(|_| {
                zero_out(self.ptr, self.cap);
                keep_on_fork(self.ptr, self.cap)
            })
            .and_then(|_| do_dump_core(self.ptr, self.cap))
            .and_then(|_| unlock_memory(self.ptr, self.cap))
            .and_then(|_| sec_free(self.ptr, self.cap))
        {
            log::error!("CRITICAL Error: failed to drop: {e:?}");
            sec_free(self.ptr, self.cap).unwrap();
            std::process::abort();
        }
    }
}

pub fn calc_page_aligned_size(required_size: usize) -> std::io::Result<usize> {
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
    let aligned_size = (sum / pagesize)
        .checked_mul(pagesize)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Size overflow"))?;
    Ok(aligned_size)
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

/// Lock memory to prevent swapping (mlock/VirtualLock)
fn lock_memory(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc::mlock(ptr.as_ptr() as *mut libc::c_void, len as libc::size_t) == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    unsafe {
        if winapi::um::memoryapi::VirtualLock(
            ptr.as_ptr() as winapi::um::memoryapi::PVOID,
            len as winapi::um::winnt::SIZE_T,
        ) == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Unlock memory (munlock/VirtualUnlock)
fn unlock_memory(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc::munlock(ptr.as_ptr() as *mut libc::c_void, len as libc::size_t) == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    unsafe {
        if winapi::um::memoryapi::VirtualUnlock(
            ptr.as_ptr() as winapi::um::memoryapi::PVOID,
            len as winapi::um::winnt::SIZE_T,
        ) == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Mark memory to be wiped on fork (Linux only)
fn wipe_on_fork(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::madvise(
            ptr.as_ptr() as *mut libc::c_void,
            len,
            libc::MADV_WIPEONFORK,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Remove fork-wiping attribute (Linux only)
fn keep_on_fork(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::madvise(
            ptr.as_ptr() as *mut libc::c_void,
            len,
            libc::MADV_KEEPONFORK,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Exclude memory from core dumps
fn dont_dump_core(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::madvise(ptr.as_ptr() as *mut libc::c_void, len, libc::MADV_DONTDUMP) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    unsafe {
        if libc::madvise(ptr.as_ptr() as *mut libc::c_void, len, libc::MADV_NOCORE) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Remove core dump exclusion
fn do_dump_core(ptr: NonNull<u8>, len: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::madvise(ptr.as_ptr() as *mut libc::c_void, len, libc::MADV_DODUMP) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    unsafe {
        if libc::madvise(ptr.as_ptr() as *mut libc::c_void, len, libc::MADV_CORE) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Get system page size
fn get_page_size() -> usize {
    #[cfg(unix)]
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }

    #[cfg(windows)]
    unsafe {
        use winapi::um::sysinfoapi;

        let mut info: sysinfoapi::SYSTEM_INFO = std::mem::zeroed();
        sysinfoapi::GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

/// Validate allocation size is page-aligned
fn check_alignment(size: usize) -> std::io::Result<()> {
    let pagesize = *PAGESIZE;

    if size % pagesize != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Size must be multiple of alignment",
        ));
    }
    Ok(())
}

/// Allocate secure memory region
fn sec_allocate(size: usize) -> std::io::Result<NonNull<u8>> {
    #[cfg(unix)]
    let ptr = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        ptr as *mut u8
    };

    #[cfg(windows)]
    let ptr = unsafe {
        use winapi::um::memoryapi;
        use winapi::um::winnt;

        let ptr = memoryapi::VirtualAlloc(
            ptr::null_mut(),
            size,
            winnt::MEM_RESERVE | winnt::MEM_COMMIT,
            winnt::PAGE_NOACCESS,
        );

        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }

        ptr as *mut u8
    };

    let non_null = NonNull::new(ptr).ok_or_else(|| {
        // log::error!("failed to create non-null pointer");
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Allocation failed")
    })?;

    Ok(non_null)
}

/// Free secure memory region
fn sec_free(ptr: NonNull<u8>, size: usize) -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc::munmap(ptr.as_ptr() as *mut libc::c_void, size) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    #[cfg(windows)]
    unsafe {
        if winapi::um::memoryapi::VirtualFree(
            ptr as winapi::um::winnt::LPVOID,
            0,
            winapi::um::winnt::MEM_RELEASE,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Set memory protection level for a region
fn protect_memory(ptr: NonNull<u8>, size: usize, prot: ProtectionMode) -> std::io::Result<()> {
    // check_alignment(size)?;

    #[cfg(unix)]
    {
        let flag = prot.to_linux_prot();
        unsafe {
            if libc::mprotect(ptr.as_ptr() as *mut libc::c_void, size, flag) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    #[cfg(windows)]
    {
        let flag = prot.to_windows_prot();
        let mut old_flag = 0;
        unsafe {
            if winapi::um::memoryapi::VirtualProtect(
                ptr as winapi::um::winnt::LPVOID,
                size,
                flag,
                &mut old_flag,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn pkey_alloc(flags: u32, access_rights: u32) -> i32;
    fn pkey_free(pkey: i32) -> i32;
    fn pkey_mprotect(addr: *mut libc::c_void, len: usize, prot: i32, pkey: i32) -> i32;
    fn pkey_set(pkey: i32, rights: u32) -> i32;
}

fn mpk_protect(ptr: NonNull<u8>, size: usize, prot: ProtectionMode) -> std::io::Result<i32> {
    unsafe {
        let pkey = pkey_alloc(0, 0);
        if pkey == -1 {
            return Err(std::io::Error::last_os_error());
        }

        if pkey_mprotect(
            ptr.as_ptr() as *mut libc::c_void,
            size,
            prot.to_linux_prot(),
            pkey,
        ) == -1
        {
            mpk_free(pkey)?;
            return Err(std::io::Error::last_os_error());
        }

        Ok(pkey)
    }
}

pub fn mpk_free(pkey: i32) -> std::io::Result<()> {
    if unsafe { pkey_free(pkey) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn mpk_set(pkey: i32, prot: ProtectionMode) -> std::io::Result<()> {
    if unsafe { pkey_set(pkey, prot.to_thread_rights()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(dead_code)]
fn supports_mpk() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            return cpuinfo.contains("pku") && cpuinfo.contains("ospke");
        }
        unsafe {
            let pkey = libc::syscall(libc::SYS_pkey_alloc, 0, 0);
            if pkey != -1 {
                libc::syscall(libc::SYS_pkey_free, pkey);
                return true;
            }
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
