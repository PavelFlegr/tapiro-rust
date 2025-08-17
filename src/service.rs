use argon2::{Argon2, PasswordHash, password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString}};
use sqlx::types::Uuid;

use crate::AppState;

pub async fn update_links(
    state: AppState,
    user_id: i64,
    links: &Vec<String>,
) -> bool {
    match sqlx::query!("UPDATE users SET links = $1 WHERE id = $2", links, user_id)
        .execute(&state.pg_pool)
        .await {
        Ok(_) => {
            return true;
        }
        Err(err) => {
            eprintln!("Error updating links: {}", err);
            return false;
        }
    }
}   

pub enum LoginOutcome {
    Success(i64),
    Failed,
    Error,
}

pub async fn login_user(
    state: AppState,
    email: &str,
    password: &str,
) -> LoginOutcome {
    let res = sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", email)
        .fetch_one(&state.pg_pool)
        .await;
    match res {
        Ok(row) => {
            let id = row.id;
            let password_hash = match PasswordHash::new(&row.password_hash) {
                Ok(hash) => hash,
                Err(err) => {
                    eprintln!("Failed to parse password hash {:?}", err);
                    return LoginOutcome::Error;
                }
            };
            let argon2 = Argon2::default();
            if argon2.verify_password(password.as_bytes(), &password_hash).is_ok() {
                return LoginOutcome::Success(id);
            } else {
                return LoginOutcome::Failed;
            }
        },
        Err(err) => {
            eprintln!("Error fetching user: {}", err);
            return LoginOutcome::Failed
        }
    }
}

pub enum RegisterOutcome {
    Success(i64),
    EmailExists,
    Error,
}

pub async fn register_user(state: AppState, email: &str, password: &str, name: &str) -> RegisterOutcome {
    let rng = OsRng::default();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(rng);
    let password_hash = match argon2.hash_password(password.as_bytes(), &salt) { 
        Ok(hash) => hash.to_string(),
        Err(err) => {
            eprintln!("Failed to hash password: {:?}", err);
            return RegisterOutcome::Error;
        }
    };
    let res = sqlx::query!("INSERT INTO users (name, password_hash, email) VALUES ($1, $2, $3) returning id", name, password_hash, email)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => {
            return RegisterOutcome::Success(row.id);
        },
        Err(err) => {
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.code().as_deref() == Some("23505") {
                    // Postgres unique constraint violation
                    return RegisterOutcome::EmailExists;
                }
            }
            eprintln!("Error inserting user: {}", err);
            return RegisterOutcome::Error;
        }
    };
}

pub enum AssignOutcome {
    Success,
    Error,
}

pub async fn assign_tag(state: AppState, uuid: Uuid, user_id: i64) -> AssignOutcome {
    let res = sqlx::query!("INSERT INTO tags (id, user_id) VALUES ($1, $2)", uuid, user_id)
        .execute(&state.pg_pool)
        .await;
    
    match res {
        Ok(_) => {
           return AssignOutcome::Success;
        },
        Err(err) => {
            eprintln!("Error assigning tag: {}", err);
            return AssignOutcome::Error;
        }
        
    }
}

pub struct TagDetails {
    pub name: String,
    pub initial: char,
    pub links: Vec<String>,
}

pub async fn get_tag_details(state: AppState, uuid: Uuid) -> Option<TagDetails> {
    let res = sqlx::query!("SELECT links, name FROM users JOIN tags on tags.user_id = users.id WHERE tags.id = $1", uuid)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => {
            let name = row.name.to_string();  
            return Some(TagDetails { 
                name: name, 
                initial: row.name.chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('U'), 
                links: row.links,
             });
        },
        Err(err) => {
            match err {
                sqlx::Error::RowNotFound => {}
                _ => eprintln!("Error fetching tag details: {}", err)
            }
            return None;
        }
    }
    
}

pub async fn get_user_links(state: AppState, user_id: i64) -> Option<Vec<String>> {
    let res = sqlx::query!("SELECT links FROM users WHERE id = $1", user_id)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => Some(row.links),
        Err(err) => {
            eprintln!("Error fetching user links: {}", err);
            return None;
        }
    }
}