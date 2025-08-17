use std::{str::FromStr, vec};

use askama::Template;
use axum::{extract::{Path, Query, State}, http::StatusCode, response::{Html, IntoResponse, Redirect, Response}};
use axum_extra::extract::Form;
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;
use tower_sessions::Session;

use crate::{service::LoginOutcome, AppState};

use crate::service;

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

    match service::update_links(state, session_data.user_id, &input.links).await {
        true => {
            return render_edit_template(&input.links, vec!["Links updated successfully".to_string()], vec![]);
        },
        false => {
            return render_edit_template(&input.links, vec![], vec!["Something went wrong, please try again".to_string()]);
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
    let res = service::login_user(state, &input.email, &input.password).await;
    match res {
        LoginOutcome::Success(user_id) => {
            let session_result = session.insert("data", SessionData {
                user_id,
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
        },
        LoginOutcome::Failed => {
            return render_login_template(&input.tag, vec!["Invalid email or password".to_string()]);
        },
        LoginOutcome::Error => {
            return render_login_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
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
    let res = service::register_user(state, &input.email, &input.password, &input.name).await;
    match res {
        service::RegisterOutcome::Success(user_id) => {
            let session_result = session.insert("data", SessionData {
                user_id,
                email: input.email.clone(),
            }).await;
            if session_result.is_err() {
                eprintln!("Failed to insert session data: {:?}", session_result.err());
                return render_register_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
            }
            // Registration successful, redirect to assign or edit
            if let Some(tag) = input.tag {
                return Redirect::to(format!("/assign/{}", tag).as_str()).into_response();
            } else {
                return Redirect::to("/edit").into_response();
            }
        },
        service::RegisterOutcome::EmailExists => {
            return render_register_template(&input.tag, vec!["Email already exists".to_string()]);
        },
        service::RegisterOutcome::Error => {
            return render_register_template(&input.tag, vec!["Something went wrong, please try again".to_string()]);
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

    let res = service::assign_tag(state, uuid, session_data.user_id).await;
    match res {
        service::AssignOutcome::Success => {
            return Redirect::to("/edit").into_response();
        },
        service::AssignOutcome::Error => {
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
    let res = service::get_tag_details(state, uuid).await;
    match res {
        Some(tag_details) => {
            let template = TagTemplate {
                name: tag_details.name,
                initial: tag_details.initial,
                links: tag_details.links,
            };
            HtmlTemplate(template).into_response()
        },
        None => Redirect::to(format!("/assign/{}", uuid).as_str()).into_response(),
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

    let res = service::get_user_links(state, session_data.user_id).await;

    match res {
        Some(links) => {
            return render_edit_template(&links, vec![], vec![]);
        },
        None => {
            return render_edit_template(&vec![], vec![], vec!["Something went wrong, please try again".to_string()]);
        }
    }
}

pub fn render_edit_template(links: &Vec<String>, messages: Vec<String>, errors: Vec<String>) -> Response {
    let template = EditTemplate { links: links.clone(), messages, errors };
    HtmlTemplate(template).into_response()
}
