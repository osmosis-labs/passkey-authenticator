use alloc::format;
use alloc::string::String;
use core::fmt::Debug;
use cosmwasm_std::StdError;
use derive_more::Display;

use crate::BT;

pub type Secp256R1Result<T> = core::result::Result<T, Secp256R1VerifyError>;

#[derive(Debug, Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum InvalidPoint {
    #[display("Invalid input length for point (must be in compressed format): Expected {expected}, actual: {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[display("Invalid point")]
    DecodingError {},
}

#[derive(Display, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Secp256R1VerifyError {
    #[display("Crypto error: {msg}")]
    GenericErr { msg: String, backtrace: BT },
    #[display("Invalid hash format")]
    InvalidHashFormat { backtrace: BT },
    #[display("Invalid public key format")]
    InvalidPubkeyFormat { backtrace: BT },
    #[display("Invalid signature format")]
    InvalidSignatureFormat { backtrace: BT },
    #[display("Invalid recovery parameter. Supported values: 0 and 1.")]
    InvalidRecoveryParam { backtrace: BT },
    #[display("Invalid point: {source}")]
    InvalidPoint { source: InvalidPoint, backtrace: BT },
}

impl Secp256R1VerifyError {
    pub fn generic_err(msg: impl Into<String>) -> Self {
        Secp256R1VerifyError::GenericErr {
            msg: msg.into(),
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_hash_format() -> Self {
        Secp256R1VerifyError::InvalidHashFormat {
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_pubkey_format() -> Self {
        Secp256R1VerifyError::InvalidPubkeyFormat {
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_signature_format() -> Self {
        Secp256R1VerifyError::InvalidSignatureFormat {
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_recovery_param() -> Self {
        Secp256R1VerifyError::InvalidRecoveryParam {
            backtrace: BT::capture(),
        }
    }
}
impl From<InvalidPoint> for Secp256R1VerifyError {
    #[track_caller]
    fn from(value: InvalidPoint) -> Self {
        Self::InvalidPoint {
            source: value,
            backtrace: BT::capture(),
        }
    }
}

impl From<Secp256R1VerifyError> for StdError {
    fn from(err: Secp256R1VerifyError) -> Self {
        match err {
            Secp256R1VerifyError::GenericErr { msg, .. } => StdError::generic_err(msg),
            Secp256R1VerifyError::InvalidHashFormat { .. } => {
                StdError::generic_err("Invalid hash format")
            }
            Secp256R1VerifyError::InvalidPubkeyFormat { .. } => {
                StdError::generic_err("Invalid public key format")
            }
            Secp256R1VerifyError::InvalidSignatureFormat { .. } => {
                StdError::generic_err("Invalid signature format")
            }
            Secp256R1VerifyError::InvalidRecoveryParam { .. } => {
                StdError::generic_err("Invalid recovery parameter")
            }
            Secp256R1VerifyError::InvalidPoint { source, .. } => match source {
                InvalidPoint::InvalidLength { expected, actual } => StdError::generic_err(format!(
                    "Invalid input length for point: Expected {expected}, actual: {actual}"
                )),
                InvalidPoint::DecodingError {} => StdError::generic_err("Invalid point"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_err_works() {
        let error = Secp256R1VerifyError::generic_err("something went wrong in a general way");
        match error {
            Secp256R1VerifyError::GenericErr { msg, .. } => {
                assert_eq!(msg, "something went wrong in a general way")
            }
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_hash_format_works() {
        let error = Secp256R1VerifyError::invalid_hash_format();
        match error {
            Secp256R1VerifyError::InvalidHashFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_signature_format_works() {
        let error = Secp256R1VerifyError::invalid_signature_format();
        match error {
            Secp256R1VerifyError::InvalidSignatureFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_pubkey_format_works() {
        let error = Secp256R1VerifyError::invalid_pubkey_format();
        match error {
            Secp256R1VerifyError::InvalidPubkeyFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }
}
