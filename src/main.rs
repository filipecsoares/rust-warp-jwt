mod auth;
mod user;

use serde::{Deserialize, Serialize};
use warp::{Filter, Reply};

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
}

#[tokio::main]
async fn main() {
    // Create initial users
    let users = vec![
        user::User::new(String::from("user1@example.com"), auth::hash_password("password1").unwrap()),
        user::User::new(String::from("user2@example.com"), auth::hash_password("password2").unwrap()),
    ];
    let state = warp::any().map(move || users.clone());

    let register_route = warp::path("register")
        .and(warp::post())
        .and(warp::body::json())
        .and(state.clone())
        .and_then(register_user);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(state.clone())
        .and_then(login);

    warp::serve(register_route.or(login_route)).run(([127, 0, 0, 1], 3030)).await;
}

async fn register_user(user: user::User, mut users: Vec<user::User>) -> Result<impl Reply, warp::Rejection> {
    // Check if the user already exists
    if users.iter().any(|u| u.email == user.email) {
        return Ok(warp::reply::json(&Message {
            message: "User already exists".to_string(),
        }));
    }

    // Hash the password
    let password_hash = auth::hash_password(&user.password);

    // Create a new user with the hashed password
    let user = user::User {
        password: password_hash.unwrap(),
        ..user
    };

    // Add the new user to the list of users
    users.push(user);

    Ok(warp::reply::json(&Message {
        message: "User registered successfully".to_string(),
    }))
}

async fn login(user: user::User, users: Vec<user::User>) -> Result<impl Reply, warp::Rejection> {
    // Find the user by username
    if let Some(found_user) = users.iter().find(|u| u.email == user.email) {
        // Verify the password
        let verified_password = auth::verify_password(&user.password, &found_user.password);
        match verified_password {
            Ok(true) => {
                // Generate a JWT token for successful login
                let token = auth::generate_jwt(&user.email, "secret_key");
                return Ok(warp::reply::json(&token));
            },
            _ => return Ok(warp::reply::json(&"Invalid username or password")),
        }
    } else {
        Ok(warp::reply::json(&"Invalid username or password"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_user() {
        let user = user::User::new(String::from("testuser"), auth::hash_password("testpassword").unwrap());
        let users = vec![];

        let response = register_user(user, users).await.unwrap();
        let response = response.into_response();
        
        assert_eq!(response.status(), 200);
    }
}