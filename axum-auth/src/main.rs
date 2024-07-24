use anyhow::Result;
use chrono::{DateTime, Utc};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{fmt::Layer, layer::SubscriberExt, util::SubscriberInitExt, Layer as _};

use std::{
  collections::HashSet,
  fs::{read_to_string, File},
  io::Write,
  net::SocketAddr,
};

use axum::{
  async_trait,
  body::Body,
  extract::FromRequestParts,
  http::{request::Parts, Request, StatusCode},
  middleware::{from_fn, Next},
  response::IntoResponse,
  routing::{get, post},
  Json, Router,
};

const JWT_DURATION: u64 = 60 * 60 * 24;
const JWT_ISS: &str = "my_service";
const JWT_AUD: &str = "my_app";

#[derive(Debug, Serialize, Deserialize)]
struct User {
  username: String,
  created_at: DateTime<Utc>,
  scope: Vec<String>,
}

struct AuthUser(User);

#[derive(Debug, Serialize, Deserialize)]
struct TokenRequest {
  username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
  token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
  let layer = Layer::new().with_filter(LevelFilter::INFO);
  tracing_subscriber::registry().with(layer).init();
  let app = Router::new().route("/login", post(get_token)).route(
    "/protected",
    get(protected_route).layer(from_fn(auth_middleware)),
  );

  let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
  info!("Listening on {}", &addr);
  let listener = TcpListener::bind(&addr).await?;
  axum::serve(listener, app.into_make_service()).await?;

  Ok(())
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
  S: Send + Sync,
{
  type Rejection = StatusCode;

  async fn from_request_parts<'life0, 'life1>(
    parts: &'life0 mut Parts,
    _state: &'life1 S,
  ) -> Result<Self, Self::Rejection>
  where
    'life0: 'async_trait,
    'life1: 'async_trait,
    Self: 'async_trait,
  {
    let token = parts
      .headers
      .get("Authorization")
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.strip_prefix("Bearer "))
      .ok_or(StatusCode::UNAUTHORIZED)?;
    let user = verify(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(AuthUser(user))
  }
}

async fn protected_route(AuthUser(user): AuthUser) -> impl IntoResponse {
  format!(
    "Hello, {}! Your scopes are: {:?}",
    user.username, user.scope
  )
}

async fn get_token(Json(payload): Json<TokenRequest>) -> Result<Json<TokenResponse>, StatusCode> {
  let user = User {
    username: payload.username,
    created_at: Utc::now(),
    scope: vec!["read".to_string(), "write".to_string()],
  };
  let token = sign(user).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
  Ok(Json(TokenResponse { token }))
}

#[allow(unused)]
fn generate_and_verify_token() -> Result<()> {
  // generate_and_save_keys()?;
  let user = User {
    username: "hal".to_string(),
    created_at: Utc::now(),
    scope: vec!["read".to_string(), "write".to_string()],
  };
  let token = sign(user)?;
  println!("Token: {}", &token);
  let claims = verify(&token).unwrap();
  println!("Claims: {:?}", claims);
  Ok(())
}

async fn auth_middleware(
  AuthUser(user): AuthUser,
  req: Request<Body>,
  next: Next,
) -> impl IntoResponse {
  info!("Authenticated user: {}", user.username);
  next.run(req).await
}

fn sign(user: impl Into<User>) -> Result<String> {
  let private_key_pem = read_to_string("private_key.pem")?;
  let key_pair = Ed25519KeyPair::from_pem(&private_key_pem)?;

  let user = user.into();
  let claims = Claims::with_custom_claims(user, Duration::from_secs(JWT_DURATION));
  let claims = claims.with_issuer(JWT_ISS).with_audience(JWT_AUD);

  let token = key_pair.sign(claims)?;
  Ok(token)
}

fn verify(token: &str) -> Result<User, Box<dyn std::error::Error>> {
  let public_key_pem = read_to_string("public_key.pem")?;
  let public_key = Ed25519PublicKey::from_pem(&public_key_pem)?;

  let options = VerificationOptions {
    allowed_issuers: Some(HashSet::from_strings(&[JWT_ISS])),
    allowed_audiences: Some(HashSet::from_strings(&[JWT_AUD])),
    ..Default::default()
  };

  let claims = public_key.verify_token::<User>(token, Some(options))?;
  Ok(claims.custom)
}

#[allow(unused)]
fn generate_and_save_keys() -> Result<()> {
  let key_pair = Ed25519KeyPair::generate();

  // 保存私钥（只包含私钥信息）
  let private_key_pem = key_pair.to_pem();
  let mut private_key_file = File::create("private_key.pem")?;
  private_key_file.write_all(private_key_pem.as_bytes())?;

  // 保存公钥（只包含公钥信息）
  let public_key_pem = key_pair.public_key().to_pem();
  let mut public_key_file = File::create("public_key.pem")?;
  public_key_file.write_all(public_key_pem.as_bytes())?;

  Ok(())
}
