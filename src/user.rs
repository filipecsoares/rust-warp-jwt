use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    uuid: String,
    email: String,
    username: String,
    password: String,
}

impl User {
    fn new(uuid: String, email: String, username: String, password: String) -> Self {
        Self {
            uuid,
            email,
            username,
            password,
        }
    }
}
