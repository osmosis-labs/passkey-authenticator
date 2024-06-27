//! Adapted from <https://github.com/daimo-eth/p256-verifier/blob/master/test/WebAuthn.t.sol>
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{ecdsa::Signature, elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, PublicKey};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};

use crate::{secp256r1_verify, Secp256R1Result};

/// Verifies a WebAuthn assertion using ECDSA secp256r1.
///
/// This function checks the authenticity of a WebAuthn assertion by verifying
/// the signature against the provided public key and challenge, following
/// the WebAuthn standards for the assertion verification procedure.
///
/// # Arguments
///
/// * `authenticator_data` - The authenticator data as per WebAuthn spec,
///   which includes flags and counters.
/// * `client_data_json` - The client data in JSON format provided by the client,
///   which includes the challenge and other metadata.
/// * `challenge` - The original challenge sent to the client during the WebAuthn
///   request.
/// * `x` - The x-coordinate of the public key in affine coordinates.
/// * `y` - The y-coordinate of the public key in affine coordinates.
/// * `r` - The r value of the ECDSA signature.
/// * `s` - The s value of the ECDSA signature.
///
/// # Returns
///
/// A result indicating whether the signature is valid (`Ok(true)`) or not (`Ok(false)`).
/// Errors are returned if there are issues with the verification process.
#[allow(clippy::too_many_arguments)]
pub fn webauthn_verify(
    authenticator_data: &[u8],
    client_data_json: &str,
    challenge: &[u8],
    x: &[u8],
    y: &[u8],
    r: &[u8],
    s: &[u8],
) -> Secp256R1Result<bool> {
    // We are making a lot of assumptions here about the coordinates, such as:
    //
    // - the length of the encoded bytes being correct
    // - the point being an element of the curve
    // - the conversion from the encoded coorinate to an affine point succeeding
    // - the affine point actually being a valid public key
    // - the signature could actually exist like this for a secp256r1 ECDSA key
    //
    // In production this should have proper error handling
    let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let public_key = PublicKey::from_encoded_point(&point).unwrap();
    let signature = Signature::from_scalars(
        GenericArray::clone_from_slice(r),
        GenericArray::clone_from_slice(s),
    )
    .unwrap();

    // This is missing some checks of some bit flags
    if authenticator_data.len() < 37 {
        return Ok(false);
    }

    // Is this an assertion?
    if !client_data_json.contains("webauthn.get") {
        return Ok(false);
    }

    // fails if the client data contains the challenge
    let b64_challenge: alloc::string::String = URL_SAFE_NO_PAD.encode(challenge);
    if !client_data_json.contains(b64_challenge.as_str()) {
        return Ok(false);
    }

    // Verify :D
    let mut hasher = Sha256::new();
    hasher.update(authenticator_data);
    hasher.update(Sha256::digest(client_data_json));
    let hash = hasher.finalize();

    secp256r1_verify(&hash, &signature.to_bytes(), &public_key.to_sec1_bytes()).map_err(Into::into)
}
