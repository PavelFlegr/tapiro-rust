mod controller;

use axum::{
    http::{Request, StatusCode}, routing::{get, post}, Router, ServiceExt
};


use sqlx::{postgres::PgPoolOptions, Pool};
use tower_http::normalize_path::{ NormalizePathLayer};
use tower_sessions::{cookie::time::Duration, Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;
use tower_layer::Layer;

use crate::controller::{landing, login, register, update_links, tag, assign, edit, login_user, register_user, assign_tag};

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

