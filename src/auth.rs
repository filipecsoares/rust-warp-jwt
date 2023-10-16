use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, SaltString
    },
    Argon2, PasswordVerifier
};
use serde::{Serialize, Deserialize};

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

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error>{
    let argon2 = Argon2::default();
    let hash = PasswordHash::new(&hash)?;
    Ok(argon2.verify_password(password.as_bytes(), &hash).is_ok())
}

#[cfg(test)]
mod tests {
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
}