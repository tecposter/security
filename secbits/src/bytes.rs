use std::sync::atomic::{AtomicUsize, Ordering};

use crate::mem::{SecSpace, calc_page_aligned_size, zero_out};

/// Secure byte container with access-control semantics
///
/// This structure provides:
/// - Reader counting for concurrent access
/// - Secure wipe on deallocation
/// - Guard-based access control
pub struct SecBytes {
    mem: SecSpace,
    len: usize,
    reader_count: AtomicUsize,
}

impl SecBytes {
    /// Create byte container with pre-allocated capacity
    pub fn with_capacity(cap: usize) -> Result<Self, std::io::Error> {
        Ok(Self {
            mem: SecSpace::with_capacity(cap)?,
            len: 0,
            reader_count: AtomicUsize::new(0),
        })
    }

    /// Get current data length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if container is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Create empty secure byte container
    pub fn new() -> Result<Self, std::io::Error> {
        let sec_bytes = Self::with_capacity(0)?;
        Ok(sec_bytes)
    }

    /// Create from existing byte slice
    ///
    /// Securely copies data into new protected memory region
    pub fn from_bytes(input: impl AsMut<[u8]>) -> Result<Self, std::io::Error> {
        let mut sec_bytes = Self::new()?;
        sec_bytes.edit()?.append(input)?;
        Ok(sec_bytes)
    }

    /// Create a read guard for immutable access
    ///
    /// Enables read-only access and tracks concurrent readers
    pub fn view(&self) -> Result<SecReadBytes, std::io::Error> {
        SecReadBytes::build(self)
    }

    /// Create a write guard for mutable access
    ///
    /// Enables exclusive write access (blocks concurrent readers)
    pub fn edit(&mut self) -> Result<SecWriteBytes, std::io::Error> {
        SecWriteBytes::build(self)
    }
}

/// Guard for read access to secure bytes
pub struct SecReadBytes<'a>(&'a SecBytes);

impl<'a> SecReadBytes<'a> {
    pub fn build(sbs: &'a SecBytes) -> Result<Self, std::io::Error> {
        let prev = sbs.reader_count.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            if let Err(e) = sbs.mem.set_readonly() {
                sbs.reader_count.fetch_sub(1, Ordering::AcqRel);
                return Err(e);
            }
        }
        Ok(SecReadBytes(sbs))
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.mem.as_mut_ptr(), self.0.len) }
    }
}

impl Drop for SecReadBytes<'_> {
    fn drop(&mut self) {
        let prev = self.0.reader_count.fetch_sub(1, Ordering::AcqRel);

        if prev == 1 {
            if let Err(e) = self.0.mem.set_noaccess() {
                log::error!("Failed to set no-access mode: {e:?}");
            }
        }
    }
}

/// Guard for write access to secure bytes
pub struct SecWriteBytes<'a>(&'a mut SecBytes);

impl<'a> SecWriteBytes<'a> {
    pub fn build(sbs: &'a mut SecBytes) -> Result<Self, std::io::Error> {
        // Exclusive access guaranteed by &mut - no atomic checks needed
        sbs.mem.set_readwrite()?;
        Ok(SecWriteBytes(sbs))
    }

    pub fn as_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0.mem.as_mut_ptr(), self.0.len) }
    }

    pub fn append(&mut self, input: impl AsMut<[u8]>) -> Result<(), std::io::Error> {
        self.write(self.0.len(), input)
    }

    pub fn write(
        &mut self,
        offset: usize,
        mut input: impl AsMut<[u8]>,
    ) -> Result<(), std::io::Error> {
        let data = input.as_mut();
        let required_cap = offset.checked_add(data.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Size overflow")
        })?;

        if required_cap > self.0.mem.capacity() {
            self.resize(required_cap)?;
        }

        // self.mem.set_readwrite()?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.0.mem.as_mut_ptr().add(offset),
                data.len(),
            );
            self.0.len = (offset + data.len()).max(self.0.len);
        }

        // Securely erase source data
        if !data.is_empty() {
            let ptr = std::ptr::NonNull::new(data.as_mut_ptr())
                .expect("Failed to turn slice to non-null pointer");
            zero_out(ptr, data.len());
        }
        // self.mem.set_noaccess()?;
        Ok(())
    }

    fn resize(&mut self, required_size: usize) -> Result<(), std::io::Error> {
        let aligned_size = calc_page_aligned_size(required_size)?;
        let new_mem = SecSpace::with_capacity(aligned_size)?;
        new_mem.set_readwrite()?;
        unsafe {
            std::ptr::copy_nonoverlapping(self.0.mem.as_mut_ptr(), new_mem.as_mut_ptr(), self.0.len)
        }
        // new_mem.set_noaccess()?;
        let _old_mem = std::mem::replace(&mut self.0.mem, new_mem);
        Ok(())
    }
}

impl Drop for SecWriteBytes<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.mem.set_noaccess() {
            log::error!("Failed to set no-access mode: {e:?}");
        }
    }
}
