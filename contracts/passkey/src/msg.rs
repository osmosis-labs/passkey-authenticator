use cosmwasm_schema::{cw_serde, QueryResponses};
pub use osmosis_std::types::osmosis::poolmanager::v1beta1::SwapAmountInRoute;

// re-export the structs from osmosis_authenticators
pub use osmosis_authenticators::AuthenticatorSudoMsg as SudoMsg;

#[cw_serde]
pub enum DenomRemovalTarget {
    All,
    Partial(Vec<String>),
}

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    TransferAdmin {
        address: String,
    },
    ClaimAdminTransfer {},
    RejectAdminTransfer {},
    CancelAdminTransfer {},
    RevokeAdmin {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(AdminResponse)]
    Admin {},

    #[returns(AdminCandidateResponse)]
    AdminCandidate {},
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
