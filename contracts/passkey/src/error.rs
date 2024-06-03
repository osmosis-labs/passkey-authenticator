use thiserror::Error;

use cosmwasm_std::StdError;
use crypto::Secp256R1VerifyError;

use crate::{authenticator::AuthenticatorError, passkey::PasskeyError};

/// Never is a placeholder to ensure we don't return any errors
#[derive(Error, Debug)]
pub enum Never {}

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Authenticator error: {0}")]
    AuthenticatorError(#[from] AuthenticatorError),

    #[error("Passkey error: {0}")]
    PasskeyError(#[from] PasskeyError),

    #[error("Invalid public key format")]
    InvalidPubkeyFormat(#[from] Secp256R1Error),
}

#[derive(Error, Debug)]
pub enum Secp256R1Error {
    #[error("{0}")]
    VerifyError(#[from] Secp256R1VerifyError),
}

impl From<Secp256R1Error> for StdError {
    fn from(err: Secp256R1Error) -> Self {
        match err {
            Secp256R1Error::VerifyError(verify_error) => match verify_error {
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
                    InvalidPoint::InvalidLength { expected, actual } => {
                        StdError::generic_err(format!(
                            "Invalid input length for point: Expected {expected}, actual: {actual}"
                        ))
                    }
                    InvalidPoint::DecodingError {} => StdError::generic_err("Invalid point"),
                },
            },
        }
    }
}
