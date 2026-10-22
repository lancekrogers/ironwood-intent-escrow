//! A 2-of-3 FROST escrow on Zcash Ironwood.
//!
//! The plan of record is festival `ironwood-intent-escrow-II0001`. The
//! decisions this crate implements are in `docs/decisions/`.

pub mod address;
pub mod attest;
pub mod block_cache;
pub mod checker;
pub mod cosign;
pub mod error;
pub mod escrow_account;
mod files;
pub mod frost;
pub mod light;
pub mod near;
pub mod note;
pub mod policy;
pub mod quote;
pub mod run;
pub mod view;
pub mod wallet;

pub use error::Error;
