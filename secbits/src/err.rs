use thiserror::Error;

/// Custom error type for secure memory operations
#[derive(Debug, Error)]
pub enum SecError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Allocation failed")]
    AllocationFailed,

    #[error("System call failed: {0}")]
    SyscallFailed(#[from] std::io::Error),

    #[error("Memory protection violation")]
    ProtectionViolation,
}
