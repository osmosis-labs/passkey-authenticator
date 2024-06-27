use cosmwasm_std::Binary;
use crypto::verify_webauthn_assertion;
use serde::Deserialize;

#[derive(Deserialize)]
struct WebAuthnTestData {
    authenticator_data: Binary, // Typically a byte array
    client_data_json: Binary,   // JSON formatted string
    challenge: Binary,          // Raw challenge bytes
    signature: Binary,          // DER-encoded ECDSA signature
    public_key: Binary,         // X9.62 encoded public key
}

#[test]
fn test_verify_webauthn_assertion() {
    use std::fs;

    const TEST_DATA_FILE: &str = "./testdata/verify_webauthn_assertion_tests.json";

    let data = fs::read_to_string(TEST_DATA_FILE).expect("Unable to read test data file");
    let json_data: WebAuthnTestData =
        serde_json::from_str(&data).expect("JSON was not well-formatted");

    println!(
        "Decoded authenticator_data: {:?}",
        json_data.authenticator_data
    );
    let client_data_json = std::str::from_utf8(json_data.client_data_json.as_slice()).expect("Invalid UTF-8");
    println!("Decoded client_data_json: {}", client_data_json);
    println!("Decoded challenge: {:?}", json_data.challenge);
    println!("Decoded signature: {:?}", json_data.signature);
    println!("Decoded public_key: {:?}", json_data.public_key);

    let result = verify_webauthn_assertion(
        &json_data.authenticator_data,
        client_data_json,
        &json_data.challenge,
        &json_data.signature,
        &json_data.public_key,
    );

    
    println!("verifing client_data_json:\n{}", client_data_json);
    println!("with challenge:\n{}", json_data.challenge);
    assert!(client_data_json.contains(&format!("{}",json_data.challenge)));
    match result {
        Err(actual_err) => {
            let actual_msg = format!("{}", actual_err);
            panic!("failed {}", actual_msg)
        }
        _ => panic!("unexpected"),
    }

    assert!(true, "Verification failed when it should have succeeded");
}
