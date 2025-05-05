use std::sync::atomic::{AtomicUsize, Ordering};

use crate::mem::{SecMem, zero_out};

/// Secure byte buffer with automatic expansion
pub struct SecBytes {
    mem: SecMem,
    len: usize,
    reader_count: AtomicUsize,
}

impl SecBytes {
    /// Creates new buffer with specified initial capacity
    pub fn with_capacity(cap: usize) -> Result<Self, std::io::Error> {
        Ok(Self {
            mem: SecMem::new(cap)?,
            len: 0,
            reader_count: AtomicUsize::new(0),
        })
    }

    /// Appends data to the buffer, securely erasing the source.
    /// Takes ownership of the input slice by zeroing it.
    pub fn append(&mut self, mut input: impl AsMut<[u8]>) -> Result<(), std::io::Error> {
        let data = input.as_mut();
        let required_cap = self.len.checked_add(data.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Size overflow")
        })?;

        if required_cap > self.mem.capacity() {
            self.resize(required_cap)?;
        }

        self.mem.set_readwrite()?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.mem.as_mut_ptr().add(self.len),
                data.len(),
            );
            self.len += data.len();
        }

        // Securely erase source data
        if !data.is_empty() {
            let ptr = std::ptr::NonNull::new(data.as_mut_ptr())
                .expect("Failed to turn slice to non-null pointer");
            zero_out(ptr, data.len());
        }
        self.mem.set_noaccess()?;
        Ok(())
    }

    /// Resizes the buffer while maintaining security guarantees.
    /// Note: Old memory is retained until overwritten and will be
    /// securely erased when dropped
    fn resize(&mut self, required_size: usize) -> Result<(), std::io::Error> {
        let new_mem = SecMem::new(required_size)?;
        new_mem.set_readwrite()?;
        unsafe {
            std::ptr::copy_nonoverlapping(self.mem.as_mut_ptr(), new_mem.as_mut_ptr(), self.len)
        }
        new_mem.set_noaccess()?;
        let _old_mem = std::mem::replace(&mut self.mem, new_mem);
        Ok(())
    }

    /// Creates new buffer initialized with provided data
    pub fn new(mut input: impl AsMut<[u8]>) -> Result<Self, std::io::Error> {
        let data = input.as_mut();
        let mut sec_bytes = Self::with_capacity(data.len())?;
        sec_bytes.append(data)?;
        Ok(sec_bytes)
    }

    /// Returns slice view of the contained data
    pub fn read(&self) -> Result<SecReadBytes, std::io::Error> {
        SecReadBytes::build(self)
    }

    /// Returns mutable slice view of the contained data
    pub fn write(&mut self) -> Result<SecWriteBytes, std::io::Error> {
        SecWriteBytes::build(self)
    }
}

pub struct SecReadBytes<'a>(&'a SecBytes);

impl<'a> SecReadBytes<'a> {
    pub fn build(sbs: &'a SecBytes) -> Result<Self, std::io::Error> {
        let prev = sbs.reader_count.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            sbs.mem.set_readonly()?;
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
        println!("SecReadBytes::drop: {prev}");

        if prev == 1 {
            if let Err(e) = self.0.mem.set_noaccess() {
                log::error!("Failed to set no-access mode: {e:?}");
            }
        }
    }
}

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
}

impl Drop for SecWriteBytes<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.mem.set_noaccess() {
            log::error!("Failed to set no-access mode: {e:?}");
        }
    }
}
