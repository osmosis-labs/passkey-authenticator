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
    #[error("Invalid hash format")]
    InvalidHashFormat,
    #[error("Invalid public key format")]
    InvalidPubkeyFormat,
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Generic crypto error: {0}")]
    GenericCryptoError(String),
}

// Implement From<CryptoError> for ContractError
impl From<Secp256R1VerifyError> for ContractError {
    fn from(err: Secp256R1VerifyError) -> Self {
        match err.code() {
            3 => ContractError::InvalidHashFormat,
            4 => ContractError::InvalidSignatureFormat,
            5 => ContractError::InvalidPubkeyFormat,
            10 => ContractError::GenericCryptoError(err.to_string()),
            _ => ContractError::GenericCryptoError(format!("Unknown crypto error: {}", err)),
        }
    }
}
