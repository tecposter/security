# SecBits

A Rust library for secure memory handling with enhanced protection against common vulnerabilities and memory inspection attacks.

## Features
- 🔒 Secure memory allocation with page alignment
- 🧹 Automatic secure zeroing before deallocation
- 🔐 Memory locking to prevent swapping to disk
- 🛡️ Fork protection (Linux) to wipe memory on fork
- 🚫 Core dump exclusion to prevent sensitive data leaks
- 🔑 Fine-grained access control with read/write guards

## Security Properties

- Confidentiality: Memory is locked and wiped on release
- Integrity: Write access is controlled via guards
- Availability: Prevents accidental exposure via core dumps
- Least Privilege: Memory starts as no-access, transitions only when needed


**Use Case**: Sensitive data handling (cryptographic keys, passwords, PII)

## Installation

Add to Cargo.toml:

```toml
[dependencies]
secbits = "0.3.0"
```


## Quick Start

```rust
use secbits::SecBytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create secure storage
    let mut secret = SecBytes::from_bytes("my_secret".as_bytes().to_vec())?;

    // Store sensitive data (source gets zeroed)
    secret.edit()?.append(b"extra data".to_vec())?;

    // Read access
    {
        let view = secret.view()?;
        assert_eq!(view.as_slice(), b"my_secretextra data");
    } // drop view

    // Write access (exclusive)
    {
        let mut edit = secret.edit()?;
        edit.as_slice()[..3].copy_from_slice(b"NEW");
    } // drop edit

    println!("{:?}", std::str::from_utf8(secret.view()?.as_slice()));
    assert_eq!(secret.view()?.as_slice(), b"NEWsecretextra data");

    Ok(())
} // Memory automatically unlocked and zeroed here
```

## Major Components

### 1. SecSpace Core

```rust
pub struct SecSpace {
    ptr: NonNull<u8>, // Non-null pointer to memory region
    cap: usize,       // Capacity in bytes (always page-aligned)
    pkey: Option<i32>,
}
```

Key Features:

- 📐 Page-Aligned Allocations: Always uses system page size multiples
- 🛡️ Protection Modes:
    - `ProtectionMode::None` - No access (default)
    - `ProtectionMode::Read` - Read-only
    - `ProtectionMode::ReadWrite` - Read-write
- ☠️ Secure Drop:
    - Set memory to RW mode
    - Zero using platform-secure methods
    - Unlock and deallocate


### 2. SecBytes Buffer

```rust
pub struct SecBytes {
    mem: SecSpace,
    len: usize,
    reader_count: AtomicUsize,
}
```

Key Features:

- 📈 Dynamic Resizing: Maintains 2x growth factor
- 👀 Access Views:
    - `SecReadBytes`: Shared read access (RO mode)
    - `SecWriteBytes`: Exclusive write access (RW mode)
- 🧵 Concurrency Safety:
    - Multiple readers allowed
    - Writers get exclusive access via &mut


## Key Tricks

### 1. Safe Memory Management

```rust
// Always use RAII guards
{
    let view = secret.read()?;  // Auto sets RO
    // use view...
} // Auto resets to NOACCESS
```

### 2. Secure Data Handling

```rust
// Source data gets zeroed automatically
secret.edit()?.append(&mut sensitive_data)?;
```

## 🔒 Security Considerations

Guarantees

- 🛡️ Memory never swapped to disk (mlock)
- 🚫 Sensitive data excluded from core dumps
- 🕵️ Defeats heap inspection attacks
- 🧠 Prevents compiler optimizations from skipping zeroing

Limitations

-  ⚠️ Requires CAP_IPC_LOCK on Linux (or root)
-  💾 Physical memory still potentially recoverable
-  🔌 Doesn't protect against hardware attacks
