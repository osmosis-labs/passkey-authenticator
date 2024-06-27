use crate::authenticator::{self};
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SudoMsg, VerifyResponse};
// use crate::state::ADDRESS;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use crypto::{secp256r1_verify, webauthn_verify};
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
        } => to_json_binary(&verify_secp256r1(
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
        } => to_json_binary(&verify_webauthn(
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

pub fn verify_secp256r1(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<VerifyResponse, ContractError> {
    // Check if the message length is valid (e.g., not empty)
    if message.is_empty() {
        return Err(ContractError::InvalidHashFormat);
    }
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
pub fn verify_webauthn(
    authenticator_data: &[u8],
    client_data_json: &str,
    challenge: &[u8],
    x: &[u8],
    y: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<VerifyResponse, ContractError> {
    let verifies = webauthn_verify(authenticator_data, client_data_json, challenge, x, y, r, s)?;
    Ok(VerifyResponse { verifies })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, OwnedDeps};
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
    fn instantiate_works() {
        setup();
    }

    enum AssertResult<T, E> {
        IsResult(T),
        IsError(E),
    }

    macro_rules! test_query {
        (
            $test_name:ident,
            $msgs:expr,
            $assert:expr,
            $deps:expr
        ) => {
            #[test]
            fn $test_name() {
                let deps = $deps.unwrap_or_else(setup);
                for msg in $msgs.iter() {
                    match $assert {
                        AssertResult::IsResult(expected) => {
                            let response: VerifyResponse =
                                from_json(query(deps.as_ref(), mock_env(), msg.clone()).unwrap())
                                    .unwrap();
                            assert_eq!(response, expected);
                        }
                        AssertResult::IsError(expected) => {
                            let err = query(deps.as_ref(), mock_env(), msg.clone()).unwrap_err();
                            assert_eq!(err, expected);
                        }
                    };
                }
            }
        };
    }

    use base64::{engine::general_purpose, Engine as _};

    test_query!(
        test_secp256r1_verify_with_js_values,
        vec![
            QueryMsg::VerifySecp256R1Signature {
                message: general_purpose::STANDARD.decode(&"ed3IwP7TaxoLZ4GJQ6FTq/vD7q4kJ4PjzFRATLKwRyA=").unwrap().into(),
                signature: general_purpose::STANDARD.decode(&"eTOhdL7n6vGzaPKA28lFm6ULrRREAQza88p6oG8GSIGzOEZIjftW6w/QckPWwjm7T2VLppfVZiouG8uG3A00ew==").unwrap().into(),
                public_key: general_purpose::STANDARD.decode(&"BNjNEupcZ/L4oAwRJIk+3PpnVMTWzt5r4TvfIpXIEKl/paidLSo2DAyppNbHye1LKNPhmdZify5pbWicMQpbD0g=").unwrap().into(),
            }
        ],
        AssertResult::IsResult(VerifyResponse { verifies: false }),
        None
    );

    test_query!(
        secp256r1_signature_verify_works,
        vec![QueryMsg::VerifySecp256R1Signature {
            message: hex::decode(&SECP256R1_MESSAGE_HEX).unwrap().into(),
            signature: hex::decode(&SECP256R1_SIGNATURE_HEX).unwrap().into(),
            public_key: hex::decode(&SECP256R1_PUBLIC_KEY_HEX).unwrap().into(),
        }],
        AssertResult::IsResult(VerifyResponse { verifies: true }),
        None
    );

    test_query!(
        secp256r1_signature_verify_fails,
        vec![QueryMsg::VerifySecp256R1Signature {
            message: hex::decode(&&{
                let mut message = hex::decode(SECP256R1_MESSAGE_HEX).unwrap();
                message[0] ^= 0x01;
                hex::encode(message)
            })
            .unwrap()
            .into(),
            signature: hex::decode(&SECP256R1_SIGNATURE_HEX).unwrap().into(),
            public_key: hex::decode(&SECP256R1_PUBLIC_KEY_HEX).unwrap().into(),
        }],
        AssertResult::IsResult(VerifyResponse { verifies: false }),
        None
    );

    test_query!(
        secp256r1_signature_verify_errors_on_invalid_hash_format,
        vec![QueryMsg::VerifySecp256R1Signature {
            message: Binary(vec![]),
            signature: hex::decode(&SECP256R1_SIGNATURE_HEX).unwrap().into(),
            public_key: hex::decode(&SECP256R1_PUBLIC_KEY_HEX).unwrap().into(),
        }],
        AssertResult::IsError(ContractError::InvalidHashFormat),
        None
    );

    test_query!(
        secp256r1_signature_verify_errors_on_invalid_public_key_format,
        vec![QueryMsg::VerifySecp256R1Signature {
            message: hex::decode(&SECP256R1_MESSAGE_HEX).unwrap().into(),
            signature: hex::decode(&SECP256R1_SIGNATURE_HEX).unwrap().into(),
            public_key: hex::decode(&{ hex::encode(vec![]) }).unwrap().into(),
        }],
        AssertResult::IsError(ContractError::InvalidPubkeyFormat),
        None
    );

    test_query!(
        secp256r1_signature_verify_errors_on_invalid_signature_format,
        vec![QueryMsg::VerifySecp256R1Signature {
            message: hex::decode(&SECP256R1_MESSAGE_HEX).unwrap().into(),
            signature: hex::decode(&&{ hex::encode(vec![]) }).unwrap().into(),
            public_key: hex::decode(&SECP256R1_PUBLIC_KEY_HEX).unwrap().into(),
        }],
        AssertResult::IsError(ContractError::InvalidSignatureFormat),
        None
    );

    test_query!(
        webauthn_verify_works,
        vec![QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json: WEBAUTHN_CLIENT_DATA_JSON.into(),
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: WEBAUTHN_SIGNATURE_R.into(),
            s: WEBAUTHN_SIGNATURE_S.into(),
        }],
        AssertResult::IsResult(VerifyResponse { verifies: true }),
        None
    );

    test_query!(
        webauthn_verify_fails_on_invalid_signature,
        vec![QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json: WEBAUTHN_CLIENT_DATA_JSON.into(),
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: {
                let mut r = WEBAUTHN_SIGNATURE_R.to_vec();
                r[0] ^= 3;
                r.into()
            },
            s: WEBAUTHN_SIGNATURE_S.into(),
        }],
        AssertResult::IsResult(VerifyResponse { verifies: false }),
        None
    );

    test_query!(
        webauthn_verify_fails_on_invalid_signature2,
        vec![QueryMsg::VerifyWebauthn {
            authenticator_data: WEBAUTHN_AUTHENTICATOR_DATA.into(),
            client_data_json: {
                let mut client_data_json = WEBAUTHN_CLIENT_DATA_JSON.to_string();
                client_data_json.push_str("tampering with hashes is fun");
                client_data_json
            },
            challenge: WEBAUTHN_CHALLENGE.into(),
            x: WEBAUTHN_PUBLIC_KEY_X.into(),
            y: WEBAUTHN_PUBLIC_KEY_Y.into(),
            r: {
                let mut r = WEBAUTHN_SIGNATURE_R.to_vec();
                r[0] ^= 3;
                r.into()
            },
            s: WEBAUTHN_SIGNATURE_S.into(),
        }],
        AssertResult::IsResult(VerifyResponse { verifies: false }),
        None
    );
}
