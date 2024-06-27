use core::fmt::Debug;
use derive_more::Display;

use crate::BT;

#[derive(Debug, Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum WebauthnError {
    #[display("Invalid public key format")]
    InvalidPubkeyFormat { backtrace: BT },
    #[display("Invalid signature format")]
    InvalidSignatureFormat { backtrace: BT },
    #[display("User presence flag not set")]
    UserPresenceFlagNotSet { backtrace: BT },
    #[display("User verification flag not set")]
    UserVerificationFlagNotSet { backtrace: BT },
    #[display("Invalid client data JSON")]
    InvalidClientDataJSON { backtrace: BT },
    #[display("Challenge mismatch in client data")]
    ChallengeMismatchClientData { backtrace: BT },
}

impl WebauthnError {
    /// Numeric error code that can easily be passed over the
    /// contract VM boundary.
    pub fn code(&self) -> u32 {
        match self {
            WebauthnError::InvalidSignatureFormat { .. } => 1,
            WebauthnError::InvalidPubkeyFormat { .. } => 2,
            WebauthnError::UserPresenceFlagNotSet { .. } => 3,
            WebauthnError::UserVerificationFlagNotSet { .. } => 4,
            WebauthnError::InvalidClientDataJSON { .. } => 5,
            WebauthnError::ChallengeMismatchClientData { .. } => 6,
        }
    }

    pub fn challenge_mismatch_client_data() -> Self {
        WebauthnError::ChallengeMismatchClientData {
            backtrace: BT::capture(),
        }
    }
    pub fn invalid_client_data_json() -> Self {
        WebauthnError::InvalidClientDataJSON {
            backtrace: BT::capture(),
        }
    }
    pub fn user_presence_flag_not_set() -> Self {
        WebauthnError::UserPresenceFlagNotSet {
            backtrace: BT::capture(),
        }
    }

    pub fn user_verification_flag_not_set() -> Self {
        WebauthnError::UserVerificationFlagNotSet {
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_pubkey_format() -> Self {
        WebauthnError::InvalidPubkeyFormat {
            backtrace: BT::capture(),
        }
    }

    pub fn invalid_signature_format() -> Self {
        WebauthnError::InvalidSignatureFormat {
            backtrace: BT::capture(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_challenge_mismatch_client_data() {
        let error = WebauthnError::challenge_mismatch_client_data();
        assert_eq!(error.code(), 6);
    }

    #[test]
    fn test_invalid_client_data_json() {
        let error = WebauthnError::invalid_client_data_json();
        assert_eq!(error.code(), 5);
    }

    #[test]
    fn test_user_presence_flag_not_set() {
        let error = WebauthnError::user_presence_flag_not_set();
        assert_eq!(error.code(), 3);
    }

    #[test]
    fn test_user_verification_flag_not_set() {
        let error = WebauthnError::user_verification_flag_not_set();
        assert_eq!(error.code(), 4);
    }

    #[test]
    fn test_invalid_pubkey_format() {
        let error = WebauthnError::invalid_pubkey_format();
        assert_eq!(error.code(), 2);
    }

    #[test]
    fn test_invalid_signature_format() {
        let error = WebauthnError::invalid_signature_format();
        assert_eq!(error.code(), 1);
    }

}
