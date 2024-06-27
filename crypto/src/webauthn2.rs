use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::{
    ecdsa::{check_pubkey, InvalidECDSAPubkeyFormat},
    secp256r1_verify,
    webauthn_error::WebauthnError,
};

struct InvalidWebauthnSignatureFormat;

impl From<InvalidWebauthnSignatureFormat> for WebauthnError {
    fn from(_original: InvalidWebauthnSignatureFormat) -> Self {
        WebauthnError::invalid_signature_format()
    }
}

fn read_signature(data: &[u8]) -> Result<[u8; 64], InvalidWebauthnSignatureFormat> {
    data.try_into().map_err(|_| InvalidWebauthnSignatureFormat)
}

// will throw a mismatch error if the client data does not contain the URL safe base 64 encoding of the challenge
fn check_challenge(challenge: &[u8], client_data_json: &str) -> Result<(), WebauthnError> {
    let b64_challenge: alloc::string::String = URL_SAFE_NO_PAD.encode(challenge);
    if !client_data_json.contains(b64_challenge.as_str()) {
        return Err(WebauthnError::challenge_mismatch_client_data());
    }
    Ok(())
}

/// Bit 0 of the authenticator data struct, corresponding to the "User Present" bit.
/// See https://www.w3.org/TR/webauthn-2/#flags.
const AUTH_DATA_FLAGS_UP: u8 = 0x01;

/// Bit 2 of the authenticator data struct, corresponding to the "User Verified" bit.
/// See https://www.w3.org/TR/webauthn-2/#flags.
const AUTH_DATA_FLAGS_UV: u8 = 0x04;

fn compute_authenticator_message_hash(
    authenticator_data: &[u8],
    client_data_json: &str,
    require_uv: bool,
) -> Result<[u8; 32], WebauthnError> {
    // Skip 11., 12.,
    // 11. Verify that the value of client_data_json.type is the string webauthn.get.
    // 12. Verify that the value of client_data_json.challenge equals the base64url encoding of options.challenge.
    // Skip 13., 14., 15.
    // 16. Verify that the UP bit of the flags in authenticator_data is set.
    if authenticator_data[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP {
        return Err(WebauthnError::user_presence_flag_not_set());
    }
    // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
    //     authData is set.
    if require_uv && (authenticator_data[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV {
        return Err(WebauthnError::user_verification_flag_not_set());
    }
    // skip 18.
    // 19. Let hash be the result of computing a hash over the cData using SHA-256.
    let client_data_json_hash = Sha256::digest(client_data_json.as_bytes());

    // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
    //     and hash.
    let message_hash =
        Sha256::digest(&[&authenticator_data[..], &client_data_json_hash[..]].concat());
    Ok(*message_hash.as_ref())
}

/// Verifies a WebAuthn assertion.
///
/// This function validates the authenticity of a WebAuthn assertion by checking the provided
/// public key, challenge, authenticator data, client data JSON, and signature against expected formats and values.
///
/// # Parameters
///
/// * `authenticator_data` - A byte array containing data about the authenticator and the user.
/// * `client_data_json` - A JSON string containing the client data, including the challenge.
/// * `challenge` - The original challenge issued to the authenticator, provided as a byte array. It verifies
///   that the assertion corresponds to the correct authentication request and should be a base64url-encoded
///   string, as per the WebAuthn standard.
/// * `signature` - A byte array containing the Serialized "compact" signature (64 bytes) produced by the authenticator.
/// * `public_key` - The public key of the authenticator, provided as a byte array.
///   Serialized according to SEC 2 (https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html)
///   (33 or 65 bytes). It is used to verify the signature of the assertion and must adhere to
///   the COSE_Key format specified by the WebAuthn standard.
///
/// # Compliance
///
/// This function adheres to the following standards:
/// - WebAuthn Level 1: https://www.w3.org/TR/webauthn-1/
/// - COSE Key format: https://tools.ietf.org/html/rfc8152
/// - EIP-137: Ethereum Improvement Proposal for WebAuthn: https://eips.ethereum.org/EIPS/eip-137
///
/// # Errors
///
/// Returns a `WebauthnError` if any part of the verification process fails.
///
/// # Example Usage
///
/// ```rust
/// let authenticator_data = ...; // Authenticator data as a byte array
/// let client_data_json = ...; // Client data JSON as a string
/// let challenge = ...; // Challenge as a byte array
/// let signature = ...; // Signature as a byte array
/// let public_key = ...; // Public key as a byte array
///
/// let result = verify_webauthn_assertion(authenticator_data, client_data_json, challenge, signature, public_key);
/// assert!(result.is_ok());
/// ```

pub fn verify_webauthn_assertion(
    authenticator_data: &[u8],
    client_data_json: &str,
    challenge: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, WebauthnError> {
    check_pubkey(public_key)?;
    let signature = read_signature(signature)?;

    check_challenge(challenge, client_data_json)?;
    let message_hash =
        compute_authenticator_message_hash(authenticator_data, client_data_json, false)?;
    // Verify the signature
    secp256r1_verify(&message_hash, &signature, &public_key).or(Ok(false))
}

impl From<InvalidECDSAPubkeyFormat> for WebauthnError {
    fn from(_original: InvalidECDSAPubkeyFormat) -> Self {
        WebauthnError::invalid_pubkey_format()
    }
}

#[cfg(test)]
mod tests {
    // use std::println;

    use std::{print, println};

    use super::*;
    use alloc::{format, string::String};
    // use base64::engine::general_purpose;

    // use alloc::format;
    // use alloc::vec;
    // use hex_literal::hex;
    // Test data (replace with valid test vectors)
    // const VALID_AUTHENTICATOR_DATA: &[u8] =
    //     &hex!("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001");
    // const VALID_CLIENT_DATA_JSON: &str = r#"{"type":"webauthn.get","challenge":"dGVzdENoYWxsZW5nZQ==","origin":"https://example.com"}"#;
    // const VALID_CHALLENGE: &[u8] = b"testChallenge";
    // const VALID_SIGNATURE: &[u8] = &hex!("304502201d215a7e60bb7dcd1dde680ac10adcaf1f16f2ceff7ad9fb9d90458837f77293022100a8a10f4dcebb73e5fd5fc3bc0c0a7fb78e3f2dc08ec1b87ed134a9c1032c76e7");
    // const VALID_PUBLIC_KEY: &[u8] = &[
    //     0x04, 0x36, 0x58, 0x5a, 0x06, 0xc5, 0xc5, 0x53, 0x4c, 0x48, 0xe2, 0x18, 0x13, 0xd6, 0xcc,
    //     0x3c, 0x0a, 0x68, 0x7e, 0x19, 0xac, 0xa1, 0xd4, 0x0e, 0xa3, 0xe1, 0xf0, 0x72, 0x1d, 0x94,
    //     0x41, 0x55, 0x6e, 0x0e, 0x9a, 0x8d, 0xfb, 0xfa, 0x59, 0xfa, 0x1e, 0xbb, 0x64, 0xd5, 0xb1,
    //     0xce, 0xea, 0x7d, 0x4b, 0xc3, 0xa1, 0x2c, 0xce, 0xa6, 0xf8, 0xa3, 0xed, 0x8b, 0x3b, 0xb9,
    //     0x5f, 0x67, 0x48, 0x63, 0x0,
    // ];

    use serde::{Deserialize, Serialize};
    #[derive(Serialize, Deserialize, Debug)]
    struct WebauthnVerifyQuery {
        authenticator_data: String,
        client_data_json: String,
        challenge: String,
        signature: String,
        public_key: String,
    }
    impl WebauthnVerifyQuery {
        fn decode_webauthn_data(json_data: &str) -> Self {
            serde_json::from_str(json_data).expect("JSON was not well-formatted")
        }
    }
    const TEST_JSON: &str = r#"
    {
        "authenticator_data": "49960d4f7c92b69c4359dcdd3b63fd17a4e56dbb9edcbd123c71b41e8d08c5e200000000010100000000000000000000000000000000000000000000000000000000000000",
        "client_data_json": "{\"type\":\"webauthn.get\",\"challenge\":\"z5W8ev8ZGHZc-EwV3mjN1A\",\"origin\":\"https://example.com\",\"crossOrigin\":false}",
        "challenge": "cf96bc7aff1918765cf84c15de68cdd4",
        "signature": "3046022100c15d56d8e4c6bdbbd89f36063d49a5d84744cfcab10e50c648df702cf68d358e02210094e6a35d2c7897a5e2da8f2b0fc2bb7e80c78e5d3a7b7b3f50d2edab7b6eabb4",
        "public_key": "04c59a9aef75c20a4f00b4a9b32df32e59e949c2f6fd41e9b4a9b17a6a2b4c20d4d2c26ebee7fd7d7c2e51cb3eaaf9a3c6347b2fbd9b2f5e6eaf0b09a616d6f3c7"
    }            
    "#;

    #[test]
    fn test_decode_webauthn_data() {
        let data = WebauthnVerifyQuery::decode_webauthn_data(TEST_JSON);

        let authenticator_data = hex::decode(&data.authenticator_data).expect("Decoding hex failed");
        let challenge = hex::decode(&data.challenge).expect("Decoding hex failed");
        let signature = hex::decode(&data.signature).expect("Decoding hex failed");
        let public_key = hex::decode(&data.public_key).expect("Decoding hex failed");

        // assert_eq!(authenticator_data.len(), 32);
        // assert_eq!(challenge.len(), 32);
        assert_eq!(signature.len(), 64); // Ensure signature length is 64
        // assert!(public_key.len() == 33 || public_key.len() == 65);
        // let result: Result<bool, WebauthnError> = verify_webauthn_assertion(&authenticator_data, &data.client_data_json, &challenge, &signature, &public_key);
        //         match result {
        //     Ok(actual) => panic!("Expected an error, got Ok({})", actual),
        //     Err(actual_err) => {
        //         let actual_msg = format!("{}", actual_err);
        //         println!("Actual error: {}", actual_msg);
        //         assert_eq!(actual_msg, "Challenge mismatch in client data");
        //     }
        // }
        // assert!(verify_webauthn_assertion(&authenticator_data, &data.client_data_json, &challenge, &signature, &public_key).unwrap());
        // Print statements for debugging
        // println!("Authenticator Data: {:?}", authenticator_data);
        // println!("Client Data JSON: {}", data.client_data_json);
        // println!("Challenge: {:?}", challenge);
        // println!("Signature: {:?}", signature);
        // println!("Public Key: {:?}", public_key);
    }
    
    // #[test]
    // fn test_valid_assertion() {
    //     let data = WebauthnVerifyQuery::decode_webauthn_data(TEST_JSON);

    //     let authenticator_data = hex::decode(&data.authenticator_data).expect("Decoding hex failed");
    //     let challenge = hex::decode(&data.challenge).expect("Decoding hex failed");
    //     let signature = hex::decode(&data.signature).expect("Decoding hex failed");
    //     let public_key = hex::decode(&data.public_key).expect("Decoding hex failed");

    //     let result = verify_webauthn_assertion(
    //         &authenticator_data,
    //         &data.client_data_json,
    //         &challenge,
    //         &signature,
    //         &public_key,
    //     );

    //     assert_eq!(result.unwrap(), true);
    // }

    // enum Expected {
    //     Ok(bool),
    //     Err(&'static str),
    // }

    // macro_rules! webauthn_test {
    //     ($name:ident, $authenticator_data:expr, $client_data_json:expr, $challenge:expr, $signature:expr, $public_key:expr, $expected:expr) => {
    //         #[test]
    //         fn $name() {
    //             let result = verify_webauthn_assertion(
    //                 $authenticator_data,
    //                 $client_data_json,
    //                 $challenge,
    //                 $signature,
    //                 $public_key,
    //             );
    //             match (result, $expected) {
    //                 (Ok(actual), Expected::Ok(expected)) => assert_eq!(actual, expected),
    //                 (Err(actual_err), Expected::Err(expected_msg)) => {
    //                     let actual_msg = format!("{}", actual_err);
    //                     assert_eq!(actual_msg, expected_msg);
    //                 }
    //                 _ => panic!("Result does not match expected outcome"),
    //             }
    //         }
    //     };
    // }

    // #[test]
    // fn test_challenge_mismatch() {
    //     let authenticator_data = vec![0; 37];
    //     let client_data_json = r#"{"type":"webauthn.get","challenge":"different_challenge","origin":"https://example.com","crossOrigin":false}"#;
    //     let challenge = vec![0; 32];
    //     let signature = vec![0; 64];
    //     let public_key = vec![0; 65];

    //     let result = verify_webauthn_assertion(
    //         &authenticator_data,
    //         client_data_json,
    //         &challenge,
    //         &signature,
    //         &public_key,
    //     );

    //     match result {
    //         Err(actual_err) => {
    //             let actual_msg = format!("{}", actual_err);
    //             assert_eq!(actual_msg, "hi");
    //         }
    //         _ => panic!("unexpected")
    //     }

    // }

    // webauthn_test!(
    //     test_valid_assertion,
    //     VALID_AUTHENTICATOR_DATA,
    //     VALID_CLIENT_DATA_JSON,
    //     VALID_CHALLENGE,
    //     VALID_SIGNATURE,
    //     VALID_PUBLIC_KEY,
    //     Expected::Ok(true)
    // );

    // webauthn_test!(
    //     test_invalid_challenge,
    //     VALID_AUTHENTICATOR_DATA,
    //     VALID_CLIENT_DATA_JSON,
    //     b"invalidChallenge",
    //     VALID_SIGNATURE,
    //     VALID_PUBLIC_KEY,
    //     Expected::Err("Challenge mismatch in client data")
    // );

    // #[test]
    // fn test_invalid_challenge_debug() {
    //     let result = verify_webauthn_assertion(
    //         VALID_AUTHENTICATOR_DATA,
    //         VALID_CLIENT_DATA_JSON,
    //         b"invalidChallenge",
    //         VALID_SIGNATURE,
    //         VALID_PUBLIC_KEY,
    //     );
    //     println!("Result: {:?}", result);
    //     match result {
    //         Ok(actual) => panic!("Expected an error, got Ok({})", actual),
    //         Err(actual_err) => {
    //             let actual_msg = format!("{}", actual_err);
    //             println!("Actual error: {}", actual_msg);
    //             assert_eq!(actual_msg, "Challenge mismatch in client data");
    //         }
    //     }
    // }

    // webauthn_test!(
    //     test_invalid_public_key_format,
    //     VALID_AUTHENTICATOR_DATA,
    //     VALID_CLIENT_DATA_JSON,
    //     VALID_CHALLENGE,
    //     VALID_SIGNATURE,
    //     &[0u8; 32],
    //     Expected::Err("Invalid public key format")
    // );

    // webauthn_test!(
    //     test_invalid_signature_format,
    //     VALID_AUTHENTICATOR_DATA,
    //     VALID_CLIENT_DATA_JSON,
    //     VALID_CHALLENGE,
    //     &[0u8; 63],
    //     VALID_PUBLIC_KEY,
    //     Expected::Err("Invalid signature format")
    // );

    // webauthn_test!(
    //     test_invalid_client_data_json,
    //     VALID_AUTHENTICATOR_DATA,
    //     r#"{"type":"webauthn.get","challenge":"invalid","origin":"https://example.com"}"#,
    //     VALID_CHALLENGE,
    //     VALID_SIGNATURE,
    //     VALID_PUBLIC_KEY,
    //     Expected::Err("Invalid client data JSON")
    // );

    // webauthn_test!(
    //     test_user_presence_flag_not_set,
    //     &hex!("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630000000001"),
    //     VALID_CLIENT_DATA_JSON,
    //     VALID_CHALLENGE,
    //     VALID_SIGNATURE,
    //     VALID_PUBLIC_KEY,
    //     Expected::Err("User presence flag not set")
    // );
}
