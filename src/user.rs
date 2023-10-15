use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub uuid: String,
    pub email: String,
    pub password: String,
}

impl User {
    pub fn new(email: String, password: String) -> Self {
        let uuid = Uuid::new_v4().to_string();
        Self {
            uuid,
            email,
            password,
        }
    }
}
