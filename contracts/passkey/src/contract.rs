use crate::authenticator::{self};
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SudoMsg, VerifyResponse};
// use crate::state::ADDRESS;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use crypto::{secp256r1_verify, verify_webauthn};
use sha2::{Digest, Sha256};

// const CONTRACT_NAME: &str = "crates.io:passkey";
// const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// const MAX_LIMIT: u32 = 100;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // ExecuteMsg::TransferAdmin { address } => transfer_admin(deps, info, address),
        // ExecuteMsg::ClaimAdminTransfer {} => claim_admin_transfer(deps, info),
        // ExecuteMsg::RejectAdminTransfer {} => reject_admin_transfer(deps, info),
        // ExecuteMsg::CancelAdminTransfer {} => cancel_admin_transfer(deps, info),
        // ExecuteMsg::RevokeAdmin {} => revoke_admin(deps, info),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::OnAuthenticatorAdded(on_authenticator_added_request) => {
            authenticator::on_authenticator_added(deps, env, on_authenticator_added_request)
                .map_err(ContractError::from)
        }
        SudoMsg::OnAuthenticatorRemoved(on_authenticator_removed_request) => {
            authenticator::on_authenticator_removed(deps, env, on_authenticator_removed_request)
                .map_err(ContractError::from)
        }
        SudoMsg::Authenticate(auth_request) => authenticator::authenticate(deps, env, auth_request),
        SudoMsg::Track(track_request) => {
            authenticator::track(deps, env, track_request).map_err(ContractError::from)
        }
        SudoMsg::ConfirmExecution(confirm_execution_request) => {
            authenticator::confirm_execution(deps, env, confirm_execution_request)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::VerifySecp256R1Signature {
            message,
            signature,
            public_key,
        } => to_json_binary(&query_verify_secp256r1(
            message.as_slice(),
            signature.as_slice(),
            public_key.as_slice(),
        )?),
        QueryMsg::VerifyWebauthn {
            authenticator_data,
            client_data_json,
            challenge,
            x,
            y,
            r,
            s,
        } => to_json_binary(&query_verify_webauthn(
            &authenticator_data,
            &client_data_json,
            &challenge,
            &x,
            &y,
            &r,
            &s,
        )?),
    }
    .map_err(ContractError::from)
}

pub fn query_verify_secp256r1(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> StdResult<VerifyResponse> {
    // Hashing
    let hash = Sha256::digest(message);

    // Verification
    let result = secp256r1_verify(hash.as_ref(), signature, public_key);
    match result {
        Ok(verifies) => Ok(VerifyResponse { verifies }),
        Err(err) => Err(err.into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn query_verify_webauthn(
    authenticator_data: &[u8],
    client_data_json: &str,
    challenge: &[u8],
    x: &[u8],
    y: &[u8],
    r: &[u8],
    s: &[u8],
) -> StdResult<VerifyResponse> {
    let verifies = verify_webauthn(authenticator_data, client_data_json, challenge, x, y, r, s)?;
    Ok(VerifyResponse { verifies })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, OwnedDeps, StdError};
    use hex_literal::hex;

    const CREATOR: &str = "creator";

    const SECP256R1_MESSAGE_HEX: &str =
    "4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e";
    const SECP256R1_SIGNATURE_HEX: &str = "1cc628533d0004b2b20e7f4baad0b8bb5e0673db159bbccf92491aef61fc9620880e0bbf82a8cf818ed46ba03cf0fc6c898e36fca36cc7fdb1d2db7503634430";
    const SECP256R1_PUBLIC_KEY_HEX: &str = "04b8188bd68701fc396dab53125d4d28ea33a91daf6d21485f4770f6ea8c565dde423f058810f277f8fe076f6db56e9285a1bf2c2a1dae145095edd9c04970bc4a";

    // Vectors sourced from <https://github.com/daimo-eth/p256-verifier/blob/master/test/WebAuthn.t.sol>
    const WEBAUTHN_PUBLIC_KEY_X: &[u8] =
        &hex!("80d9326e49eb6314d03f58830369ea5bafbc4e2709b30bff1f4379586ca869d9");
    const WEBAUTHN_PUBLIC_KEY_Y: &[u8] =
        &hex!("806ed746d8ac6c2779a472d8c1ed4c200b07978d9d8d8d862be8b7d4b7fb6350");
    const WEBAUTHN_CLIENT_DATA_JSON: &str = r#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://funny-froyo-3f9b75.netlify.app"}"#;
    const WEBAUTHN_CHALLENGE: &[u8] = &hex!("74657374");
    const WEBAUTHN_AUTHENTICATOR_DATA: &[u8] =
        &hex!("e0b592a7dd54eedeec65206e031fc196b8e5915f9b389735860c83854f65dc0e1d00000000");
    const WEBAUTHN_SIGNATURE_R: &[u8] =
        &hex!("32e005a53ae49a96ac88c715243638dd5c985fbd463c727d8eefd05bee4e2570");
    const WEBAUTHN_SIGNATURE_S: &[u8] =
        &hex!("7a4fef4d0b11187f95f69eefbb428df8ac799bbd9305066b1e9c9fe9a5bcf8c4");

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {};
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        deps
    }
    #[test]
    fn secp256r1_signature_verify_works() {
        let deps = setup();

        let message = hex::decode(SECP256R1_MESSAGE_HEX).unwrap();
        let signature = hex::decode(SECP256R1_SIGNATURE_HEX).unwrap();
        let public_key = hex::decode(SECP256R1_PUBLIC_KEY_HEX).unwrap();

        let verify_msg = QueryMsg::VerifySecp256R1Signature {
            message: message.into(),
            signature: signature.into(),
            public_key: public_key.into(),
        };

        let raw: Binary = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();

        assert_eq!(res, VerifyResponse { verifies: true });
    }

    #[test]
    fn secp256r1_signature_verify_fails() {
        let deps = setup();

        let mut message = hex::decode(SECP256R1_MESSAGE_HEX).unwrap();
        // alter hash
        message[0] ^= 0x01;
        let signature = hex::decode(SECP256R1_SIGNATURE_HEX).unwrap();
        let public_key = hex::decode(SECP256R1_PUBLIC_KEY_HEX).unwrap();

        let verify_msg = QueryMsg::VerifySecp256R1Signature {
            message: message.into(),
            signature: signature.into(),
            public_key: public_key.into(),
        };

        let raw: Binary = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();

        assert_eq!(res, VerifyResponse { verifies: false });
    }

    #[test]
    fn secp256r1_signature_verify_invalid_public_key_format() {
        let deps = setup();

        let message = hex::decode(SECP256R1_MESSAGE_HEX).unwrap();
        let signature = hex::decode(SECP256R1_SIGNATURE_HEX).unwrap();
        let public_key = vec![];

        let verify_msg = QueryMsg::VerifySecp256R1Signature {
            message: message.into(),
            signature: signature.into(),
            public_key: public_key.into(),
        };

        let result = query(deps.as_ref(), mock_env(), verify_msg);
        match result {
            Err(ContractError::InvalidPubkeyFormat { .. }) => {} // Expected error
            _ => panic!("Expected an error with invalid public key format"),
        }
    }

    #[test]
    fn secp256r1_signature_verify_errors() {
        let deps = setup();

        let message = hex::decode(SECP256R1_MESSAGE_HEX).unwrap();
        let signature = hex::decode(SECP256R1_SIGNATURE_HEX).unwrap();
        let public_key = vec![];

        let verify_msg = QueryMsg::VerifySecp256R1Signature {
            message: message.into(),
            signature: signature.into(),
            public_key: public_key.into(),
        };

        let raw = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();

        assert!(!res.verifies);
    }
    #[test]
    fn webauthn_verify_works() {
        let deps = setup();
        let verify_msg = QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json: WEBAUTHN_CLIENT_DATA_JSON.into(),
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: WEBAUTHN_SIGNATURE_R.into(),
            s: WEBAUTHN_SIGNATURE_S.into(),
        };

        let raw = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();
        assert!(res.verifies);
    }

    #[test]
    fn webauthn_verify_errors() {
        let deps = setup();

        let mut r = WEBAUTHN_SIGNATURE_R.to_vec();
        r[0] ^= 3;

        let verify_msg = QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json: WEBAUTHN_CLIENT_DATA_JSON.into(),
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: r.into(),
            s: WEBAUTHN_SIGNATURE_S.into(),
        };

        let raw = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();
        assert!(!res.verifies);

        let mut client_data_json = WEBAUTHN_CLIENT_DATA_JSON.to_string();
        client_data_json.push_str("tampering with hashes is fun");
        let verify_msg = QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json,
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: WEBAUTHN_SIGNATURE_R.into(),
            s: WEBAUTHN_SIGNATURE_S.into(),
        };

        let deps = setup();
        let raw = query(deps.as_ref(), mock_env(), verify_msg).unwrap();
        let res: VerifyResponse = from_json(raw).unwrap();
        assert!(!res.verifies);
    }
}
