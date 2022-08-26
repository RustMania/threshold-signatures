//!  Multiparty threshold signature scheme
//!
//!  MPC TS scheme, as defined in ["Fast multiparty threshold ECDSA with Fast trustless setup"](https://eprint.iacr.org/2019/114.pdf)
//!
//!  The module implements following algorithms:
//! * Key generation
//! * Signing
//! * key refresh or re-sharing
//!

pub mod keygen;
pub mod messages;
pub mod protocol;
pub mod resharing;
pub mod signature;
pub mod types;
mod utils;
pub mod zk_range_proofs;

#[macro_use]
extern crate strum_macros;
