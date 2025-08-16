use std::str::FromStr;

use argon2::{password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString}, Argon2, PasswordHash};
use axum::{
    extract::{Path, Query, State}, http::{Request, StatusCode}, response::{Html, IntoResponse, Redirect, Response}, routing::{get, post}, Router, ServiceExt
};

use askama::Template;
use axum_extra::extract::Form;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, types::Uuid, Pool};
use tower_http::normalize_path::{ NormalizePathLayer};
use tower_sessions::{cookie::time::Duration, Expiry, Session, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;
use tower_layer::Layer;

#[derive(Clone)]
struct AppState {
    pg_pool: Pool<sqlx::Postgres>,
}


#[tokio::main]
async fn main() {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost/tapiro")
        .await
        .expect("Failed to connect to the database");
    let session_store = PostgresStore::new(pool.clone());
    session_store.migrate().await.expect("Failed to migrate session store");
    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));
    let state = AppState {
        pg_pool: pool,
    };   
    
    let app = Router::new()
        .route("/favicon.ico", get(|| async { (StatusCode::NOT_FOUND, "Not Found") }))
        .route("/", get(landing))
        .route("/login", get(login))
        .route("/register", get(register))
        .route("/{id}", get(tag))
        .route("/assign/{id}", get(assign))
        .route("/edit", get(edit))

        .route("/edit", post(update_links))
        .route("/login", post(login_user))
        .route("/register", post(register_user))
        .route("/assign", post(assign_tag))
        .with_state(state)
        .layer(session_layer)
    ;


    let app = NormalizePathLayer::trim_trailing_slash().layer(app);
    
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let aaa = ServiceExt::<Request<axum::body::Body>>::into_make_service(app);
    axum::serve(listener, aaa).await.unwrap();
}

#[derive(Deserialize)]
struct LinksRequest {
    links: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SessionData {
    user_id: i64,
    email: String,
}

async fn update_links(session: Session, State(state): State<AppState>, Form(input): Form<LinksRequest>) -> impl IntoResponse {
    let session_data: SessionData = session.get("data").await.expect("Failed to session data").expect("no session data found");
    
    sqlx::query!("UPDATE users SET links = $1 WHERE id = $2", &input.links, session_data.user_id)
        .execute(&state.pg_pool)
        .await
        .expect("Failed to update links");

    Redirect::to("/edit").into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    tag: Option<String>,
}
async fn login_user(session: Session, State(state): State<AppState>, Form(input): Form<LoginRequest>) -> impl IntoResponse {
    let res = sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", input.email)
        .fetch_one(&state.pg_pool)
        .await;
    match res {
        Ok(row) => {
            let id = row.id;
            let password_hash = PasswordHash::new(&row.password_hash).expect("Failed to parse password hash");
            let argon2 = Argon2::default();
            if argon2.verify_password(input.password.as_bytes(), &password_hash).is_ok() {
                session.insert("data", SessionData{
                    user_id: id,
                    email: input.email.clone(),
                }).await.expect("Failed to insert session data");
                // Password is correct, proceed with login
                if let Some(tag) = input.tag {
                    return Redirect::to(format!("/assign/{}", tag).as_str()).into_response();
                } else {
                    return Redirect::to("/edit").into_response();
                }
            } else {
                // Password is incorrect
                return (StatusCode::UNAUTHORIZED, "Invalid email or password").into_response();
            }
        },
        Err(err) => {
            eprintln!("Error fetching user: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to login").into_response();
        }
        
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    name: String,
    password: String,
    email: String,
    tag: Option<String>,
}

async fn register_user(session: Session, State(state): State<AppState>, Form(input): Form<RegisterRequest>) -> impl IntoResponse {
    let rng = OsRng::default();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(rng);
    let password_hash = argon2.hash_password(input.password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();
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
                    let template = LoginTemplate {
                        tag: input.tag.unwrap_or_default(),
                    };
                    return HtmlTemplate(template).into_response();
                }
            }
            eprintln!("Error inserting user: {}", err);
            let template = LoginTemplate {
                tag: input.tag.unwrap_or_default(),
            };
            return HtmlTemplate(template).into_response();
            }
    };

    session.insert("data", SessionData{
        user_id: id,
        email: input.email,
    }).await.expect("Failed to insert session data");

    
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
struct AssignTagRequest {
    tag: String,
}

async fn assign_tag(session: Session, State(state): State<AppState>, Form(input): Form<AssignTagRequest>) -> impl IntoResponse {
    let session_data: SessionData = session.get("data").await.expect("Failed to get session data").expect("no session data found");
    let uuid = Uuid::from_str(&input.tag).expect("Failed to parse UUID");
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

async fn landing() -> impl IntoResponse {
    let template = LandingTemplate {};
    HtmlTemplate(template)
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    tag: String,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    tag: String,
}

async fn login(Query(query): Query<LoginQuery>) -> impl IntoResponse {
    let template = LoginTemplate {
        tag: query.tag,
    };
    HtmlTemplate(template)
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    tag: String,
}

async fn register() -> impl IntoResponse {
    let template = RegisterTemplate {
        tag: "".to_string(),
    };
    HtmlTemplate(template)
}

#[derive(Template)]
#[template(path = "tag.html")]
pub struct TagTemplate {
    name: String,
    initial: char,
    links: Vec<String>,
}

async fn tag(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let uuid = Uuid::from_str(&id).expect("Failed to parse UUID");
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

async fn assign(session: Session, Path(id): Path<String>) -> impl IntoResponse {
    let logged_in: bool = session.get::<SessionData>("data").await.unwrap_or(None).is_some();

    println!("Logged in: {}", logged_in);
    let template = AssignTemplate {
        logged_in: logged_in,
        id: id,
    };
    HtmlTemplate(template)
}

#[derive(Template)]
#[template(path = "edit.html")]
pub struct EditTemplate {
    links: Vec<String>
}

async fn edit(session: Session, State(state): State<AppState>) -> impl IntoResponse {
    let session_data: SessionData = session.get("data").await.expect("Failed to get session data").expect("no session data found");
    let res = sqlx::query!("SELECT links, name FROM users WHERE id = $1", session_data.user_id)
        .fetch_one(&state.pg_pool)
        .await;

    match res {
        Ok(row) => {
            let template = EditTemplate { links: row.links };
            return HtmlTemplate(template).into_response();
        },
        Err(_) => {
            return (StatusCode::NOT_FOUND, "Tag not found").into_response();
        }
    }
}
