use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize)]
struct JwkKey {
    kty: String,
    use_: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

fn get_jwks() -> Result<Jwks, Box<dyn std::error::Error>> {
    let file = File::open("app-check-google-jwks.json")?;
    let reader = BufReader::new(file);
    let jwks: Jwks = serde_json::from_reader(reader)?;
    Ok(jwks)
}

#[derive(Clone)]
struct AppCheckVerification {
    project_number: String,

}

impl AppCheckVerification {
    fn new(project_number: String) -> Self {
        Self {
            project_number,
        }
    }

    fn verify(&self, token: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        let token = String::from_utf8(token)?;

        // Obtain the Firebase App Check Public Keys
        let jwks = get_jwks()?;

        // Verify the signature on the App Check token
        let token_data = decode::<HashMap<String, Value>>(
            &token,
            &DecodingKey::from_rsa_components(&jwks.keys[0].n, &jwks.keys[0].e),
            &Validation::new(jsonwebtoken::Algorithm::RS256),
        )?;

        let claims = token_data.claims;

        // Check issuer and audience
        if claims["iss"] != format!("https://firebaseappcheck.googleapis.com/{}", self.project_number) ||
            claims["aud"] != format!("projects/{}", self.project_number) {
            return Err("invalid issuer or audience".into());
        }

        Ok(claims["sub"].as_str().unwrap().to_string())
    }
}
