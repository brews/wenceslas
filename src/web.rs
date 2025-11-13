//! Logic for web server to use this application's services.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{info, warn};

use crate::core::{GetUserError, UnverifiedPassword, UserEmail, UserProfile, VerifyError};
use crate::service::{UserProfileGetter, Verifier};

pub struct HttpServer {
    app: axum::Router,
    listener: TcpListener,
}

impl HttpServer {
    pub async fn new(
        service: Arc<impl Verifier + UserProfileGetter>,
        host: String,
        port: String,
        apikey: Arc<Option<String>>,
    ) -> anyhow::Result<Self> {
        let server_url = format!("{host}:{port}");
        let listener = tokio::net::TcpListener::bind(server_url)
            .await
            .context("Could not bind server to the address and port")?;

        Ok(Self {
            app: app(service, apikey),
            listener,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!("listening on {}", self.listener.local_addr().unwrap());
        axum::serve(self.listener, self.app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("error from running server")?;
        Ok(())
    }
}

fn app(
    app_service: Arc<impl Verifier + UserProfileGetter>,
    apikey: Arc<Option<String>>,
) -> axum::Router {
    Router::new()
        .route("/users", get(get_user))
        .route("/verify", post(post_verify))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(apikey, auth))
        .layer(TraceLayer::new_for_http())
        .with_state(app_service)
}

async fn post_verify(
    State(service): State<Arc<impl Verifier>>,
    Json(request): Json<VerifyRequest>,
) -> Result<VerifyDecision, StatusCode> {
    info!("received request verify {:?}", request.email);
    let verify_result = service.verify(&request.email, request.password);
    // Parse verification results, log errors, respond to request with with decision.
    let decision = match verify_result {
        Ok(_) => VerifyDecision::Verified,
        Err(VerifyError::UnknownEmail) => {
            info!("no records found for {:?}", request.email);
            VerifyDecision::Unverified
        }
        Err(VerifyError::Password) => {
            info!("could not verify password for {:?}", request.email);
            VerifyDecision::Unverified
        }
        Err(VerifyError::Algorithm(e)) => {
            // Warn because recovered from error but might be an issue with stored hash or app bug.
            warn!(
                "encountered error verifying password for {:?}: {e}",
                request.email
            );
            VerifyDecision::Unverified
        }
    };

    info!("decision for {:?} is {decision:?}", request.email);
    Ok(decision)
}

async fn get_user(
    State(service): State<Arc<impl UserProfileGetter>>,
    Query(params): Query<GetUserRequest>,
) -> Result<Json<Vec<UserProfile>>, StatusCode> {
    info!("received request for user profile {:?}", params.email);
    let user_profile_result = service.get_user_profile(&params.email);

    // Digesting these with a match so we can log the outcome.
    match user_profile_result {
        Ok(r) => Ok(Json(vec![r])), // Returned in vector, even if only one user.
        Err(GetUserError::UnknownEmail) => {
            info!("no records found for {:?}", params.email);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Middleware to screen access to routes based on key in authorization header.
async fn auth(
    State(apikey): State<Arc<Option<String>>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get apikey from app state, return early if None, because then app isn't doing auth.
    let stored_apikey: &str = match apikey.as_ref() {
        Some(k) => k.as_str(),
        None => {
            info!("no APIKEY set, skipping request auth check");
            return Ok(next.run(req).await);
        }
    };

    // Get api key from request header.
    let auth_header = req
        .headers()
        .get("x-apikey")
        .and_then(|header| header.to_str().ok());
    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Check request header against valid key.
    if auth_header == stored_apikey {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Prepares server to gracefully handle shutdown signals.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    email: UserEmail,
    password: UnverifiedPassword,
}

#[derive(Deserialize)]
struct GetUserRequest {
    email: UserEmail,
}

#[derive(Debug)]
pub enum VerifyDecision {
    Verified,
    Unverified,
}

impl IntoResponse for VerifyDecision {
    fn into_response(self) -> Response {
        let decision = match self {
            VerifyDecision::Verified => true,
            VerifyDecision::Unverified => false,
        };

        let body = Json(json!({ "verified": decision }));
        (StatusCode::OK, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http};
    use tower::{Service, ServiceExt};

    use super::*;
    use crate::storage;
    use http_body_util::BodyExt; // for `collect`
    use serde_json::{Value, json};
    use std::io::Cursor;

    #[tokio::test]
    async fn test_integration_verify_route() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let app = app(Arc::new(service), Arc::new(None));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(
                            &json!({"email": "email2@foobar.com", "password": "Test123Now!"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "verified": true }));
    }

    #[tokio::test]
    async fn test_integration_verify_route_rejects_bad_apikey() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let apikey = String::from("123abcBadApiKey");
        let app = app(Arc::new(service), Arc::new(Some(apikey.clone())));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("x-apikey", "notTheCorrectApiKey")
                    .body(Body::from(
                        serde_json::to_vec(
                            &json!({"email": "email2@foobar.com", "password": "Test123Now!"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Double check the body in the response to the unauthorize request is empty and not still giving the solution.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_integration_verify_route_good_apikey() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let apikey = String::from("123abcBadApiKey");
        let app = app(Arc::new(service), Arc::new(Some(apikey.clone())));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("x-apikey", apikey)
                    .body(Body::from(
                        serde_json::to_vec(
                            &json!({"email": "email2@foobar.com", "password": "Test123Now!"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "verified": true }));
    }

    #[tokio::test]
    async fn test_integration_verify_route_fails_bad_password() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let app = app(Arc::new(service), Arc::new(None));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(
                            &json!({"email": "email2@foobar.com", "password": "ThisBetterFail"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "verified": false }));
    }

    #[tokio::test]
    async fn test_integration_verify_route_fails_bad_email() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let app = app(Arc::new(service), Arc::new(None));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(
                            &json!({"email": "this@better.fail", "password": "Test123Now!"}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "verified": false }));
    }

    #[tokio::test]
    async fn test_integration_users_route() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let app = app(Arc::new(service), Arc::new(None));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/users?email=email%40example.com")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            json!([{ "user_email": "email@example.com", "display_name": null, "first_name": null, "last_name": null, "nickname": null}])
        );
    }

    #[tokio::test]
    async fn test_integration_users_route_rejects_bad_apikey() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();
        let service = crate::service::Service::new(store);

        let apikey = String::from("123abcBadApiKey");
        let app = app(Arc::new(service), Arc::new(Some(apikey.clone())));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/users?email=email%40example.com")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("x-apikey", "notTheCorrectApiKey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Double check the body in the response to the unauthorize request is empty and not still sending a user profile.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }
}
