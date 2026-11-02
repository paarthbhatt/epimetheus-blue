//! Local HTTP API and dashboard. Loopback only: no TLS, no CORS, no sessions.
//!
//! Everything here is read-only except two verbs — `POST /api/killswitch` and
//! `POST /api/quarantine/{id}/restore`. Nothing exposed by this crate deletes
//! or writes user data. Restoring is delegated to [`Quarantine`], which refuses
//! to overwrite a file that has reappeared at the original path.

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use blue_core::{Db, Quarantine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// The dashboard is compiled into the binary; no CDN, no build step.
const DASHBOARD: &str = include_str!("../assets/index.html");

/// `GET /api/summary` returns the last N events, matching the dashboard's need.
const SUMMARY_EVENTS: usize = 20;

/// Hard ceiling on any `?limit=` value so a typo cannot ask for the world.
const MAX_LIMIT: usize = 1000;

/// `Db` has no `count` verb, so counts are derived from a deliberately generous
/// read. Beyond this many rows the dashboard shows a floor, not a lie.
const COUNT_CAP: usize = 100_000;

/// Shared handles for every request. Cheap to clone; all state lives behind arcs.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub quarantine: Arc<Quarantine>,
    /// `None` leaves the API unauthenticated (loopback default).
    pub token: Option<String>,
}

/// API error shape: `{"error": "..."}` with a matching status code.
type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, message: impl Into<String>) -> ApiError {
    (status, Json(json!({ "error": message.into() })))
}

/// `anyhow` failures are internal: log the cause, do not leak a backtrace.
fn internal(e: anyhow::Error) -> ApiError {
    tracing::warn!(error = %e, "request failed");
    err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Build the full router, dashboard and API included.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/summary", get(summary))
        .route("/artifacts", get(artifacts))
        .route("/events", get(events))
        .route("/quarantine", get(quarantine_list))
        .route("/quarantine/{id}/restore", post(restore))
        .route("/killswitch", get(killswitch_get).post(killswitch_set))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));

    Router::new()
        .route("/", get(dashboard))
        .nest("/api", api)
        .with_state(state)
}

/// Serve the router until the listener fails or the process exits.
pub async fn serve(state: AppState, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    let addr = listener.local_addr().context("reading local address")?;
    tracing::info!(%addr, auth = state.token.is_some(), "blue http listening");
    axum::serve(listener, router(state))
        .await
        .context("serving http")?;
    Ok(())
}

// ---------------------------------------------------------------- auth

/// Bearer-token gate for `/api/*`. `/` stays public: it is loopback-only and
/// serves static HTML with no data in it.
async fn require_token(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return next.run(req).await;
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(t) if constant_time_eq(t.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => err(StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response(),
    }
}

/// Length-independent comparison; a token check should not leak its prefix.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------- routes

async fn dashboard() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(DASHBOARD),
    )
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    let kill_switch = state.db.kill_switch();
    Json(json!({
        "status": if kill_switch { "degraded" } else { "ok" },
        "kill_switch": kill_switch,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn summary(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let artifacts = state
        .db
        .recent_artifacts(COUNT_CAP)
        .map_err(internal)?
        .len();
    let quarantined = state.quarantine.list(false).map_err(internal)?.len();
    let events = state.db.recent_events(SUMMARY_EVENTS).map_err(internal)?;
    Ok(Json(json!({
        "artifacts": artifacts,
        "quarantined": quarantined,
        "events": events,
        "kill_switch": state.db.kill_switch(),
    })))
}

async fn artifacts(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let limit = limit_of(&params, 50);
    let rows = state.db.recent_artifacts(limit).map_err(internal)?;
    Ok(Json(json!({ "artifacts": rows })))
}

async fn events(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let limit = limit_of(&params, 100);
    let rows = state.db.recent_events(limit).map_err(internal)?;
    Ok(Json(json!({ "events": rows })))
}

async fn quarantine_list(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let include_restored = flag_of(&params, "all");
    let rows = state.quarantine.list(include_restored).map_err(internal)?;
    Ok(Json(json!({ "quarantine": rows })))
}

async fn restore(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id: i64 = id
        .parse()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "quarantine id must be an integer"))?;

    // Distinguish "no such row" (404) from "row exists but will not restore"
    // (409) — `Quarantine::restore` reports both as `anyhow` strings.
    match state.db.quarantine_item(id) {
        Ok(None) => {
            return Err(err(
                StatusCode::NOT_FOUND,
                format!("no quarantine record {id}"),
            ))
        }
        Ok(Some(item)) if item.restored_at_ms.is_some() => {
            return Err(err(
                StatusCode::CONFLICT,
                format!("quarantine record {id} was already restored"),
            ))
        }
        Ok(Some(_)) => {}
        Err(e) => return Err(internal(e)),
    }

    match state.quarantine.restore(id) {
        Ok(path) => Ok(Json(json!({ "restored": path.to_string_lossy() }))),
        // Refusals are conflicts, not server faults: a file may have reappeared
        // at the original path, or the blob may be gone. Never overwrite.
        Err(e) => Err(err(StatusCode::CONFLICT, e.to_string())),
    }
}

async fn killswitch_get(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "kill_switch": state.db.kill_switch() }))
}

/// Accepts `{"on": true|false}`. Parsed by hand so bad input is a JSON 400
/// rather than axum's plain-text rejection.
async fn killswitch_set(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?;
    let on = value
        .get("on")
        .and_then(Value::as_bool)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, r#"expected {"on": true|false}"#))?;

    state.db.set_kill_switch(on).map_err(internal)?;
    let _ = state.db.event(
        "killswitch",
        if on { "warn" } else { "info" },
        None,
        &format!(r#"{{"on":{on}}}"#),
        blue_core::now_ms(),
    );
    tracing::warn!(on, "kill switch changed via http");
    Ok(Json(json!({ "kill_switch": on })))
}

// ---------------------------------------------------------------- params

/// `?limit=` parsed leniently: absent or malformed means "default", not a 400.
fn limit_of(params: &HashMap<String, String>, default: usize) -> usize {
    params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, MAX_LIMIT)
}

/// `?all=true|1|yes` enables the flag; anything else is false.
fn flag_of(params: &HashMap<String, String>, key: &str) -> bool {
    matches!(
        params.get(key).map(|v| v.as_str()),
        Some("true" | "1" | "yes" | "on")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use blue_core::Tier;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct Fixture {
        app: Router,
        db: Arc<Db>,
        quarantine: Arc<Quarantine>,
        _dir: tempfile::TempDir,
    }

    fn fixture(token: Option<&str>) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open_memory().unwrap());
        let quarantine = Arc::new(Quarantine::new(dir.path().join("q"), db.clone()).unwrap());
        let state = AppState {
            db: db.clone(),
            quarantine: quarantine.clone(),
            token: token.map(str::to_string),
        };
        Fixture {
            app: router(state),
            db,
            quarantine,
            _dir: dir,
        }
    }

    fn request(method: &str, uri: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn json_request(uri: &str, body: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn call(app: &Router, req: axum::http::Request<Body>) -> (StatusCode, Value) {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn health_reports_status_and_version() {
        let fx = fixture(None);
        let (status, body) = call(&fx.app, request("GET", "/api/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["status"].is_string());
        assert_eq!(body["kill_switch"], false);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn token_gates_api_but_not_dashboard() {
        let fx = fixture(Some("s3cret"));

        let (status, _) = call(&fx.app, request("GET", "/api/health")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = call(&fx.app, request("GET", "/api/summary")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let mut req = request("GET", "/api/health");
        req.headers_mut()
            .insert(header::AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        let (status, body) = call(&fx.app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kill_switch"], false);

        let mut wrong = request("GET", "/api/health");
        wrong
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer nope".parse().unwrap());
        let (status, _) = call(&fx.app, wrong).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The dashboard itself stays reachable without a token.
        let res = fx.app.clone().oneshot(request("GET", "/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn restore_of_missing_id_is_not_a_server_error() {
        let fx = fixture(None);
        let (status, body) = call(&fx.app, request("POST", "/api/quarantine/4242/restore")).await;
        assert!(status == StatusCode::NOT_FOUND || status == StatusCode::CONFLICT);
        assert!(body["error"].is_string());

        let (status, body) = call(
            &fx.app,
            request("POST", "/api/quarantine/not-a-number/restore"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn restore_refuses_to_overwrite() {
        let fx = fixture(None);
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("dup.bin");
        std::fs::write(&src, b"one").unwrap();
        let path = src.to_string_lossy().to_string();
        let art = fx.db.record_artifact(&path, "h", 3, 1, 1).unwrap();
        let stored = fx
            .quarantine
            .store(&src, art, Tier::Corroborated, "test")
            .unwrap();
        std::fs::write(&src, b"reappeared").unwrap();

        let (status, body) = call(
            &fx.app,
            request("POST", &format!("/api/quarantine/{}/restore", stored.id)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
        assert_eq!(std::fs::read(&src).unwrap(), b"reappeared");
    }

    #[tokio::test]
    async fn kill_switch_toggles_through_the_api() {
        let fx = fixture(None);
        assert!(!fx.db.kill_switch());

        let (status, body) = call(&fx.app, json_request("/api/killswitch", r#"{"on":true}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kill_switch"], true);
        assert!(fx.db.kill_switch());

        let (_, body) = call(&fx.app, request("GET", "/api/killswitch")).await;
        assert_eq!(body["kill_switch"], true);

        let (status, _) = call(&fx.app, json_request("/api/killswitch", r#"{"on":false}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!fx.db.kill_switch());

        // Bad input is a 400, never a panic.
        let (status, body) = call(
            &fx.app,
            json_request("/api/killswitch", r#"{"on":"maybe"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn summary_and_lists_survive_bad_query_values() {
        let fx = fixture(None);
        fx.db.event("scan", "info", None, "{}", 1).unwrap();

        let (status, body) = call(&fx.app, request("GET", "/api/summary")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["artifacts"], 0);
        assert_eq!(body["quarantined"], 0);
        assert_eq!(body["events"].as_array().map(Vec::len), Some(1));

        let (status, body) = call(&fx.app, request("GET", "/api/events?limit=abc")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["events"].as_array().map(Vec::len), Some(1));

        let (status, _) = call(&fx.app, request("GET", "/api/artifacts?limit=999999")).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = call(&fx.app, request("GET", "/api/quarantine?all=true")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["quarantine"].is_array());
    }
}
