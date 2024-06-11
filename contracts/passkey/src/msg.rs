use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;
pub use osmosis_std::types::osmosis::poolmanager::v1beta1::SwapAmountInRoute;

// re-export the structs from osmosis_authenticators
pub use osmosis_authenticators::AuthenticatorSudoMsg as SudoMsg;

#[cw_serde]
pub enum DenomRemovalTarget {
    All,
    Partial(Vec<String>),
}

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    // TransferAdmin { address: String },
    // ClaimAdminTransfer {},
    // RejectAdminTransfer {},
    // CancelAdminTransfer {},
    // RevokeAdmin {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // #[returns(AdminResponse)]
    // Admin {},

    // #[returns(AdminCandidateResponse)]
    // AdminCandidate {},
    /// Cosmos format (secp256r1 verification scheme).
    #[returns(VerifyResponse)]
    VerifySecp256R1Signature {
        /// Message to verify.
        message: Binary,
        /// Serialized signature. Cosmos format (64 bytes).
        signature: Binary,
        /// Serialized compressed (33 bytes) or uncompressed (65 bytes) public key.
        public_key: Binary,
    },
    /// Webauthn component verification
    #[returns(VerifyResponse)]
    VerifyWebauthn {
        /// Authenticator data
        authenticator_data: Binary,
        /// Client data (JSON encoded)
        client_data_json: String,
        /// Challenge value
        challenge: Binary,
        /// X coordinate of public key point
        ///
        /// Untagged big-endian serialized byte sequence representing the X coordinate on the secp256r1 elliptic curve
        x: Binary,
        /// Y coordinate of public key point
        ///
        /// Untagged big-endian serialized byte sequence representing the Y coordinate on the secp256r1 elliptic curve
        y: Binary,
        /// r component of signature
        ///
        /// The representation of this component is a big-endian encoded 256bit integer
        r: Binary,
        /// s component of signature
        ///
        /// The representation of this component is a big-endian encoded 256bit integer
        s: Binary,
    },
}

#[cw_serde]
pub struct VerifyResponse {
    pub verifies: bool,
}

#[cw_serde]
pub struct PasskeyResponse {
    ok: bool,
}

#[cw_serde]
pub struct AdminResponse {
    pub admin: Option<String>,
}

#[cw_serde]
pub struct AdminCandidateResponse {
    pub candidate: Option<String>,
}
