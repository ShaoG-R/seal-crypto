//! The `traits` module serves as the single entry point for all cryptographic capability traits.
//! It re-exports the individual trait definitions from its submodules.

pub mod kem;
pub mod key;
pub mod sign;
pub mod symmetric; 