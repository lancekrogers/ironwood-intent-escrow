//! A 2-of-3 FROST escrow on Zcash Ironwood.
//!
//! The plan of record is festival `ironwood-intent-escrow-II0001`. The
//! decisions this crate implements are in `docs/decisions/`.

#[cfg(feature = "native")]
pub mod address;
pub mod attest;
#[cfg(feature = "native")]
pub mod block_cache;
pub mod checker;
#[cfg(feature = "native")]
pub mod claims;
#[cfg(feature = "native")]
pub mod cosign;
pub mod error;
#[cfg(feature = "native")]
pub mod escrow_account;
#[cfg(feature = "native")]
mod files;
#[cfg(feature = "native")]
pub mod frost;
#[cfg(feature = "native")]
pub mod light;
#[cfg(feature = "native")]
pub mod near;
#[cfg(feature = "native")]
pub mod note;
#[cfg(feature = "native")]
pub mod policy;
pub mod quote;
#[cfg(feature = "native")]
pub mod run;
pub mod verify;
#[cfg(feature = "native")]
pub mod view;
#[cfg(feature = "native")]
pub mod wallet;

pub use error::Error;
