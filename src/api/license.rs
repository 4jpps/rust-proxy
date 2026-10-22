//! `/api/license`: records a Commercial License key after validating it once
//! against the license store. Informational only -- it drives the About page
//! badge and nothing in the daemon is gated on it (the AGPL build is fully
//! functional either way).

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::routes::ApiError;
use crate::db::{self, CommercialLicense};
use crate::state::AppState;

const DEFAULT_LICENSE_SERVER: &str = "https://store.jpps.us";
const PRODUCT_SLUG: &str = "rust-proxy";

fn license_server() -> String {
    std::env::var("RUST_PROXY_LICENSE_SERVER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_LICENSE_SERVER.to_string())
}

#[derive(Serialize, Debug, PartialEq)]
pub struct LicenseResponse {
    licensed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    licensee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    lifetime: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    validated_at: Option<String>,
}

impl LicenseResponse {
    fn none() -> Self {
        Self {
            licensed: false,
            licensee: None,
            key_hint: None,
            expires_at: None,
            lifetime: false,
            validated_at: None,
        }
    }

    fn from_record(lic: CommercialLicense) -> Self {
        let tail: String = lic
            .license_key
            .chars()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Self {
            licensed: true,
            licensee: Some(lic.licensee),
            key_hint: Some(format!("lic-...{tail}")),
            expires_at: lic.expires_at,
            lifetime: lic.lifetime,
            validated_at: Some(lic.validated_at),
        }
    }
}

pub async fn get_license(State(state): State<AppState>) -> Result<Json<LicenseResponse>, ApiError> {
    Ok(Json(
        match db::load_commercial_license(state.db()).await? {
            Some(lic) => LicenseResponse::from_record(lic),
            None => LicenseResponse::none(),
        },
    ))
}

#[derive(Deserialize)]
pub struct PutLicenseRequest {
    license_key: String,
}

#[derive(Deserialize)]
struct StoreValidation {
    valid: bool,
    #[serde(default)]
    status: String,
    name: Option<String>,
    expires_at: Option<String>,
    #[serde(default)]
    lifetime: bool,
    reason: Option<String>,
}

/// Asks the store whether `key` is a live rust-proxy license.
async fn validate_with_store(base_url: &str, key: &str) -> Result<CommercialLicense, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let url = format!("{}/api/v1/validate", base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "license_key": key, "product": PRODUCT_SLUG }))
        .send()
        .await
        .map_err(|_| {
            ApiError::BadGateway(
                "could not reach the license server; check this host's internet access and try again".into(),
            )
        })?;
    if !resp.status().is_success() {
        return Err(ApiError::BadGateway(format!(
            "the license server answered {}; try again later",
            resp.status().as_u16()
        )));
    }
    let v: StoreValidation = resp
        .json()
        .await
        .map_err(|_| ApiError::BadGateway("the license server sent an unreadable reply".into()))?;
    if !v.valid {
        let why = match (v.reason.as_deref(), v.status.as_str()) {
            (Some(r), _) if !r.is_empty() => r.to_string(),
            (_, s) if !s.is_empty() => s.to_string(),
            _ => "not valid".to_string(),
        };
        return Err(ApiError::BadRequest(format!(
            "that license key is not valid ({why})"
        )));
    }
    Ok(CommercialLicense {
        license_key: key.to_string(),
        licensee: v.name.unwrap_or_else(|| "Licensed customer".to_string()),
        expires_at: v.expires_at,
        lifetime: v.lifetime,
        validated_at: Utc::now().to_rfc3339(),
    })
}

pub async fn put_license(
    State(state): State<AppState>,
    Json(body): Json<PutLicenseRequest>,
) -> Result<Json<LicenseResponse>, ApiError> {
    let key = body.license_key.trim();
    if !key.starts_with("lic-") || key.len() > 100 || key.chars().any(char::is_whitespace) {
        return Err(ApiError::BadRequest(
            "license keys look like lic-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
        ));
    }
    let lic = validate_with_store(&license_server(), key).await?;
    db::set_commercial_license(state.db(), &lic).await?;
    Ok(Json(LicenseResponse::from_record(lic)))
}

pub async fn delete_license(
    State(state): State<AppState>,
) -> Result<Json<LicenseResponse>, ApiError> {
    db::clear_commercial_license(state.db()).await?;
    Ok(Json(LicenseResponse::none()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY: &str = "lic-4e7b4068-36ea-4e9a-8ca2-f98d06041b5f";

    #[tokio::test]
    async fn a_valid_key_is_accepted_and_sent_with_the_product_slug() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/validate"))
            .and(body_json(
                serde_json::json!({"license_key": KEY, "product": "rust-proxy"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true, "status": "active", "name": "Jeff Parrish PC Services LLC",
                "product": "rust-proxy", "expires_at": "2126-10-14T00:00:00Z", "lifetime": true
            })))
            .expect(1)
            .mount(&server)
            .await;
        let lic = validate_with_store(&server.uri(), KEY).await.unwrap();
        assert_eq!(lic.licensee, "Jeff Parrish PC Services LLC");
        assert!(lic.lifetime);
        assert_eq!(lic.license_key, KEY);
    }

    #[tokio::test]
    async fn an_invalid_key_surfaces_the_stores_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": false, "status": "invalid", "lifetime": false, "reason": "revoked"
            })))
            .mount(&server)
            .await;
        match validate_with_store(&server.uri(), KEY).await {
            Err(ApiError::BadRequest(m)) => assert!(m.contains("revoked"), "{m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_server_error_or_unreachable_store_is_a_bad_gateway_not_an_invalid_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(matches!(
            validate_with_store(&server.uri(), KEY).await,
            Err(ApiError::BadGateway(_))
        ));
        assert!(matches!(
            validate_with_store("http://127.0.0.1:1", KEY).await,
            Err(ApiError::BadGateway(_))
        ));
    }

    #[test]
    fn the_response_never_contains_the_full_key() {
        let r = LicenseResponse::from_record(CommercialLicense {
            license_key: KEY.into(),
            licensee: "Acme".into(),
            expires_at: None,
            lifetime: true,
            validated_at: "2026-10-14T00:00:00Z".into(),
        });
        assert_eq!(
            r.key_hint.as_deref(),
            Some("lic-...06041b5f"[..4].to_owned().as_str()).map(|_| "lic-...041b5f")
        );
        assert!(!serde_json::to_string(&r).unwrap().contains(KEY));
    }
}
