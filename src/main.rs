use axum::{
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::Parser;
use serde_json::json;

use axum::extract::Path;
use std::net::SocketAddr;

use chrono::prelude::*;

use std::str::FromStr;

#[derive(Parser)]
#[clap()]
struct Args {
    #[clap(long, default_value = "127.0.0.1")]
    ip: String,

    #[clap(long, default_value_t = 3000)]
    port: u16,

    #[clap(long, default_value = "")]
    auth_user: String,

    #[clap(long, default_value = "")]
    auth_pass: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let app = Router::new()
        .route("/", get(root))
        .route("/rcon", get(check_rcon))
        .route("/service/:name", get(check_service))
        .route("/docker/:name", get(check_docker))
        .layer(middleware::from_fn(logger));

    let addrstr = format!("{}:{}", args.ip, args.port);
    println!("Starting webserver on {}", addrstr);

    let addr = SocketAddr::from_str(&addrstr).unwrap();

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn logger<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    println!(
        "{} [{}] {}",
        Local::now().format("%Y-%m-%d %H:%m:%S"),
        method,
        path
    );

    let result = next.run(req).await;

    println!(
        "{}  =>> {}",
        Local::now().format("%Y-%m-%d %H:%m:%S"),
        result.status().as_str()
    );

    Ok(result)
}

async fn root() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, r#"¯\_(ツ)_/¯"#)
}

async fn check_rcon() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "a": "b" })))
}

async fn check_service(Path(name): Path<String>) -> impl IntoResponse {
    let servicename = name.as_str();

    (StatusCode::OK, Json(json!({ "service": servicename })))
}

async fn check_docker(Path(name): Path<String>) -> impl IntoResponse {
    let containername = name.as_str();

    (StatusCode::OK, Json(json!({ "container": containername })))
}
