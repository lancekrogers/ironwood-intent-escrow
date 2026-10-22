//! A 2-of-3 FROST escrow on Zcash Ironwood.
//!
//! The plan of record is festival `ironwood-intent-escrow-II0001`. The
//! decisions this crate implements are in `docs/decisions/`.

pub mod address;
pub mod block_cache;
pub mod cosign;
pub mod error;
mod files;
pub mod frost;
pub mod light;
pub mod note;
pub mod wallet;

pub use error::Error;
