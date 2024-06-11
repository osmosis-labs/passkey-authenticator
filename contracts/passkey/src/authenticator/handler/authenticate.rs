use cosmwasm_std::{DepsMut, Env, Response};
use crypto::secp256r1_verify;
use osmosis_authenticators::AuthenticationRequest;

use crate::{
    contract::verify_secp256r1, error::ContractError, passkey::update_and_check_passkey
};

use super::validate_and_parse_params;

pub fn authenticate(
    deps: DepsMut,
    _env: Env,
    auth_request: AuthenticationRequest,
) -> Result<Response, ContractError> {
    // TODO: @amo]
    let params = validate_and_parse_params(auth_request.authenticator_params)?;

    // let _key = (
    //     &auth_request.account,
    //     auth_request.authenticator_id.as_str(),
    // );

    // hash auth_request.msg

    // TODO: @Amosel
    // let message = auth_request.msg.value.0;
    // hash 256 of message
    // use sha2::{Sha256, Digest};
    // let message_hash = Sha256::digest(message.as_bytes());
    // let is_valid = secp256r1_verify(
    //     message_has,
    //     auth_request.signature_data,
    //     &params.pub_key
    // )?;
    
    update_and_check_passkey(deps, &params)?;

    Ok(Response::new().add_attribute("action", "authenticate"))
}
