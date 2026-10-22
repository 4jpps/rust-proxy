//! `/api/default-site`: what a request gets when its hostname matches no
//! site (NPM's Settings, Default Site).

use axum::Json;
use axum::extract::State;

use super::routes::ApiError;
use crate::config::DefaultSite;
use crate::state::AppState;

pub async fn get_default_site(State(state): State<AppState>) -> Json<DefaultSite> {
    Json((*state.default_site()).clone())
}

pub async fn put_default_site(
    State(state): State<AppState>,
    Json(mut body): Json<DefaultSite>,
) -> Result<Json<DefaultSite>, ApiError> {
    body.redirect_url = body.redirect_url.trim().to_string();
    body.validate().map_err(ApiError::BadRequest)?;
    crate::db::set_default_site(state.db(), &body).await?;
    state.set_default_site(body.clone());
    Ok(Json(body))
}
