use std::{str::FromStr, vec};

use argon2::{Argon2, PasswordHash, password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString}};
use askama::Template;
use axum::{extract::{Path, Query, State}, http::StatusCode, response::{Html, IntoResponse, Redirect, Response}};
use axum_extra::extract::Form;
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;
use tower_sessions::Session;

use crate::AppState;

#[derive(Deserialize)]
pub struct LinksRequest {
    links: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SessionData {
    user_id: i64,
    email: String,
}

pub async fn update_links(session: Session, State(state): State<AppState>, Form(input): Form<LinksRequest>) -> impl IntoResponse {
    let Some(session_data) = session.get::<SessionData>("data").await.ok().flatten()
    else {
        return Redirect::to("/login").into_response();
    };
    
    match sqlx::query!("UPDATE users SET links = $1 WHERE id = $2", &input.links, session_data.user_id)
        .execute(&state.pg_pool)
        .await {
            Ok(_) => {
                return render_edit_template(input.links, vec!["Links updated successfully".to_string()], vec![]);
            }
            Err(err) => {
                eprintln!("Error updating links: {}", err);
                return render_edit_template(input.links, vec![], vec!["Something went wrong, please try again".to_string()]);
            }
        }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
    tag: Option<String>,
}
pub async fn login_user(session: Session, State(state): State<AppState>, Form(input): Form<LoginRequest>) -> Response {
    let res = sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", input.email)
        .fetch_one(&state.pg_pool)
        .await;
    match res {
        Ok(row) => {
            let id = row.id;
            let password_hash = match PasswordHash::new(&row.password_hash) {
                Ok(hash) => hash,
                Err(err) => {
                    eprintln!("Failed to parse password hash {:?}", err);
                    return render_login_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
                }
            };
            let argon2 = Argon2::default();
            if argon2.verify_password(input.password.as_bytes(), &password_hash).is_ok() {
                let session_result = session.insert("data", SessionData{
                    user_id: id,
                    email: input.email.clone(),
                }).await;
                if session_result.is_err() {
                    eprintln!("Failed to insert session data: {:?}", session_result.err());
                    return render_login_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
                }
                // Password is correct, proceed with login
                if let Some(tag) = input.tag {
                    return Redirect::to(format!("/assign/{}", tag).as_str()).into_response();
                } else {
                    return Redirect::to("/edit").into_response();
                }
            } else {
                // Password is incorrect
                return render_login_template(&input.tag, vec!["Invalid email or password".to_string()]);
            }
        },
        Err(err) => {
            eprintln!("Error fetching user: {}", err);
            return render_login_template(&input.tag, vec!["Invalid email or password".to_string()]);
        }
        
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    name: String,
    password: String,
    email: String,
    tag: Option<String>,
}

pub async fn register_user(session: Session, State(state): State<AppState>, Form(input): Form<RegisterRequest>) -> impl IntoResponse {
    let rng = OsRng::default();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(rng);
    let password_hash = match argon2.hash_password(input.password.as_bytes(), &salt) { 
        Ok(hash) => hash.to_string(),
        Err(err) => {
            eprintln!("Failed to hash password: {:?}", err);
            return render_register_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
        }
    };
    let res = sqlx::query!("INSERT INTO users (name, password_hash, email) VALUES ($1, $2, $3) returning id", input.name, password_hash, input.email)
        .fetch_one(&state.pg_pool)
        .await;

    let id = match res {
        Ok(row) => {
            row.id
        },
        Err(err) => {
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.code().as_deref() == Some("23505") {
                    // Postgres unique constraint violation
                    return render_register_template(&input.tag, vec!["Email already exists".to_string()]);
                }
            }
            eprintln!("Error inserting user: {}", err);
            return render_register_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
        }
    };

    match session.insert("data", SessionData{
        user_id: id,
        email: input.email,
    }).await {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Failed to insert session data: {:?}", err);
        }
    }

    
    return match input.tag {
        Some(tag) => {
            Redirect::to(format!("/assign/{}", tag).as_str()).into_response()
        },
        None => {
            Redirect::to("/").into_response()
        }
    }
    
    
}

#[derive(Deserialize)]
pub struct AssignTagRequest {
    tag: String,
}

pub async fn assign_tag(session: Session, State(state): State<AppState>, Form(input): Form<AssignTagRequest>) -> impl IntoResponse {
    let uuid = match Uuid::from_str(&input.tag) {
        Ok(uuid) => uuid,
        Err(_) => {
            eprintln!("Invalid UUID format for tag: {}", input.tag);
            return Redirect::to("/").into_response();
        }
    };
    let Some(session_data) = session.get::<SessionData>("data").await.ok().flatten()
    else {
        return Redirect::to(format!("/login?tag={}", uuid).as_str()).into_response();
    };
    
    let res = sqlx::query!("INSERT INTO tags (id, user_id) VALUES ($1, $2)", uuid, session_data.user_id)
        .execute(&state.pg_pool)
        .await;
    
    match res {
        Ok(_) => {
            return Redirect::to("/edit").into_response();
        },
        Err(err) => {
            eprintln!("Error assigning tag: {}", err);
            return Redirect::to(format!("/{}", input.tag).as_str()).into_response();
        }
        
    }
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {err}"),
            )
                .into_response(),
        }
    }
}

#[derive(Template)]
#[template(path = "landing.html")]
pub struct LandingTemplate {}

pub async fn landing() -> impl IntoResponse {
    let template = LandingTemplate {};
    HtmlTemplate(template)
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    tag: String,
    errors: Vec<String>,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    tag: Option<String>,
}

pub async fn login(Query(query): Query<LoginQuery>) -> impl IntoResponse {
    render_login_template(&query.tag, vec![])
}

fn render_login_template(tag: &Option<String>, errors: Vec<String>) -> Response {
    let template = LoginTemplate {
        tag: tag.clone().unwrap_or("".to_string()),
        errors,
    };
    HtmlTemplate(template).into_response()
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    tag: String,
    errors: Vec<String>,
}

pub async fn register(Query(query): Query<LoginQuery>) -> impl IntoResponse {
    render_register_template(&query.tag, vec![])
}

fn render_register_template(tag: &Option<String>, errors: Vec<String>) -> Response {
    let template = RegisterTemplate {
        tag: tag.clone().unwrap_or("".to_string()),
        errors: errors,
    };
    HtmlTemplate(template).into_response()
}

#[derive(Template)]
#[template(path = "tag.html")]
pub struct TagTemplate {
    name: String,
    initial: char,
    links: Vec<String>,
}

pub async fn tag(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(uuid) => uuid,
        Err(_) => return Redirect::to("/").into_response(),
        
    };
    let res = sqlx::query!("SELECT links, name FROM users JOIN tags on tags.user_id = users.id WHERE tags.id = $1", uuid)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => {
            let name = row.name.to_string();  
            let initial = name.chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('U');
            let template = TagTemplate { name: name, initial: initial, links: row.links };
            return HtmlTemplate(template).into_response();
        },
        Err(_) => {
            return Redirect::to(format!("/assign/{}", uuid).as_str()).into_response();
        }
    }
    
}

#[derive(Template)]
#[template(path = "assign.html")]
pub struct AssignTemplate {
    id: String,
    logged_in: bool
}

pub async fn assign(session: Session, Path(id): Path<String>) -> Response {
    let logged_in: bool = session.get::<SessionData>("data").await.unwrap_or(None).is_some();

    println!("Logged in: {}", logged_in);
    let template = AssignTemplate {
        logged_in: logged_in,
        id: id,
    };
    HtmlTemplate(template).into_response()
}

#[derive(Template)]
#[template(path = "edit.html")]
pub struct EditTemplate {
    links: Vec<String>,
    messages: Vec<String>,
    errors: Vec<String>,
}

pub async fn edit(session: Session, State(state): State<AppState>) -> Response {
    let Some(session_data) = session.get::<SessionData>("data").await.ok().flatten()
    else {
        return Redirect::to("/login").into_response();
    };
    let res = sqlx::query!("SELECT links, name FROM users WHERE id = $1", session_data.user_id)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => {
            return render_edit_template(row.links, vec![], vec![]);
        },
        Err(_) => {
            return render_edit_template(vec![], vec![], vec!["Something went wrong, please try again".to_string()]);
        }
    }
}

pub fn render_edit_template(links: Vec<String>, messages: Vec<String>, errors: Vec<String>) -> Response {
    let template = EditTemplate { links: links.clone(), messages, errors };
    HtmlTemplate(template).into_response()
}
