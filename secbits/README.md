# SecBits

A Rust library for secure memory handling featuring:  
- 🔒 Memory locking (mlock/madvise)  
- 🛡️ Configurable protection modes (RW/RO/NOACCESS)  
- 🧼 Secure zeroing with platform-specific intrinsics  
- 🗑️ Automatic memory wiping on drop  
- 📏 Page-aligned allocations  

**Use Case**: Sensitive data handling (cryptographic keys, passwords, PII)

## Quick Start

```rust
use secbits::SecBytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create secure storage
    let mut secret = SecBytes::new()?;
    
    // Store sensitive data (source gets zeroed)
    secret.append(&mut "my_secret".as_bytes().to_vec())?;

    // Read access
    let view = secret.read()?;
    assert_eq!(view.as_slice(), b"my_secret");

    // Write access (exclusive)
    let mut edit = secret.write()?;
    edit.as_slice()[..3].copy_from_slice(b"NEW");
    
    Ok(())
} // Memory automatically unlocked and zeroed here
```

## Major Components

### 1. SecMem Core

```rust
struct SecMem {
    ptr: NonNull<u8>,
    cap: usize,      
    layout: Layout,  
}
```

Key Features:

- 📐 Page-Aligned Allocations: Always uses system page size multiples
- 🔐 Memory Locking:
    - `mlock()` prevents swapping to disk
    - `madvise(MADV_DONTDUMP)` excludes from core dumps
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
struct SecBytes {
    mem: SecMem,         
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
secret.append(&mut sensitive_data)?;
```

## 🔒 Security Considerations

Guarantees

- 🛡️ Memory never swapped to disk (mlock)
- 🚫 Sensitive data excluded from core dumps
- 🕵️♂️ Defeats heap inspection attacks
- 🧠 Prevents compiler optimizations from skipping zeroing

Limitations

-  ⚠️ Requires CAP_IPC_LOCK on Linux (or root)
-  💾 Physical memory still potentially recoverable
-  🔌 Doesn't protect against hardware attacks
