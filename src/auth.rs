use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    if password.is_empty() {
        return Err(argon2::password_hash::Error::Password);
    }
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    let password_bytes = password.as_bytes();
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password_bytes, &salt)?.to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let hash = PasswordHash::new(&hash)?;
    Ok(argon2.verify_password(password.as_bytes(), &hash).is_ok())
}

pub fn generate_jwt(email: &str, secret_key: &str) -> String {
    let expiration = (SystemTime::now() + Duration::from_secs(3600)) // 1 hour
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: email.to_string(),
        exp: expiration as usize,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Validation, decode, DecodingKey};

    use super::*;

    #[test]
    fn test_hash_password_success() {
        let password = "password123";
        let result = hash_password(password);

        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_password_failure() {
        let password = "";
        let result = hash_password(password);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_password_success() {
        let password = "password123";
        let hash = hash_password(password).unwrap();
        let result = verify_password(password, &hash);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_verify_password_failure() {
        let password = "password123";

        assert!(verify_password(password, "invalid_hash").is_err());
    }

    #[test]
    fn test_verify_password_not_equal() {
        let password = "password123";
        let hash = hash_password(password).unwrap();
        let result = verify_password("wrong_password", &hash);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    // Define your secret key here for testing purposes
    const SECRET_KEY: &str = "your_secret_key_for_testing";
    #[test]
    fn test_generate_jwt() {
        let email = "user@example.com";
        let jwt = generate_jwt(email, SECRET_KEY);

        // Decode the JWT to verify its contents
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(&jwt, &DecodingKey::from_secret(SECRET_KEY.as_bytes()), &validation);

        match token_data {
            Ok(token) => {
                assert_eq!(token.claims.sub, email);
                assert!(token.claims.exp > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize);
            }
            Err(err) => {
                panic!("JWT decoding failed: {:?}", err);
            }
        }
    }
}
