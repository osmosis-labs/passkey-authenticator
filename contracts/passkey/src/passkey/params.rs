use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct PasskeyParams {
    // pubkey: [32;u8];
    pub pub_key: Vec<u8>,
}
