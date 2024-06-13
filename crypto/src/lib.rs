#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std; // allow for file I/O during tests

mod backtrace;
mod ecdsa;
mod errors;
mod identity_digest;
mod secp256r1;
mod webauthn;

pub use crate::ecdsa::{ECDSA_PUBKEY_MAX_LEN, ECDSA_SIGNATURE_LEN, MESSAGE_HASH_MAX_LEN};

pub use crate::errors::{Secp256R1Result, Secp256R1VerifyError};
pub use crate::secp256r1::{secp256r1_recover_pubkey, secp256r1_verify};
pub(crate) use backtrace::BT;
pub use webauthn::webauthn_verify;
