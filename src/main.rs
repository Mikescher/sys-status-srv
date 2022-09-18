use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use axum::middleware;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::Json;
use axum::Router;

use clap::Parser;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::json;

use axum::extract::Path;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use chrono::prelude::*;
use chrono::Duration;

use std::str::FromStr;

use execute::Execute;

#[derive(Parser, Clone)]
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

    #[clap(long, default_value = "")]
    source_rcon_pass: String,

    #[clap(long, default_value = "127.0.0.1:27015")]
    source_rcon_address: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut app = Router::new();
    app = app.route("/", get(root));
    app = app.route("/source-rcon/:name", get({let a = args.clone(); move |path, req| check_source_rcon(path, req, a) }));
    app = app.route("/service/:name", get({let a = args.clone(); move |path, req| check_service(path, req, a) }));
    app = app.route("/docker/:name", get({let a = args.clone(); move |path, req| check_docker(path, req, a) }));
    app = app.fallback(get(notfound));
    app = app.layer(middleware::from_fn(logger));

    let addrstr = format!("{}:{}", args.ip, args.port);
    println!("Starting webserver on {}", addrstr);

    let addr = SocketAddr::from_str(&addrstr).unwrap();

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}

async fn logger<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    println!("{} [{}] {}", Local::now().format("%Y-%m-%d %H:%m:%S"), method, path);

    let result = next.run(req).await;

    println!("{}  =>> {}", Local::now().format("%Y-%m-%d %H:%m:%S"), result.status().as_str());

    Ok(result)
}

async fn root() -> impl IntoResponse {
    (StatusCode::OK, r#"¯\_(ツ)_/¯"#)
}

async fn notfound() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, r#"???"#)
}

async fn check_docker(Path(name): Path<String>, req: Request<Body>, args: Args) -> impl IntoResponse {
    if let Some(r) = auth(req, args).await {
        return r
    }

    let container_name = name.as_str();

    let out_status: String;
    let out_uptime: i64;
    let out_started_at: String;

    {
        let (mut cmd, cmdstr) = cmd("docker", vec!["inspect", "-f", "{{.State.Status}}", container_name]);

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let response = cmd.execute_output();

        let output = match response {
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "EXEC_FAILED",
                        "info": "Command::execute_output() returned an error",
                        "err": format!("{}", e)
                    })),
                )
            }
            Ok(v) => v,
        };

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

        if let Some(exit_code) = output.status.code() {
            if exit_code != 0 {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "EXIT_CODE",
                        "info": format!("docker-inspect returned exit code {}", exit_code),
                        "exit_code": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                    })),
                );
            }
        } else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "INTERRUPTED",
                    "info": "docker-inspect was interrupted",
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }

        if !stderr.is_empty() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "STDERR",
                    "info": "docker-inspect returned an error",
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }

        if stdout != "running" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "NOT_RUNNING",
                    "info": "container is not running",
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }

        out_status = stdout;
    }

    {
        let (mut cmd, cmdstr) = cmd("docker", vec!["inspect", "-f", "{{.State.StartedAt}}", container_name]);

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let response = cmd.execute_output();

        let output = match response {
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "EXEC_FAILED",
                        "info": "Command::execute_output() returned an error",
                        "err": format!("{}", e)
                    })),
                )
            }
            Ok(v) => v,
        };

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

        if let Some(exit_code) = output.status.code() {
            if exit_code != 0 {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "EXIT_CODE",
                        "info": format!("docker-inspect returned exit code {}", exit_code),
                        "exit_code": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                    })),
                );
            }
        } else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "INTERRUPTED",
                    "info": "docker-inspect was interrupted",
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }

        if !stderr.is_empty() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "STDERR",
                    "info": "docker-inspect returned an error",
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }

        let started_at = match DateTime::parse_from_rfc3339(&stdout) {
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "STARTEDAT_PARSE",
                        "info": "docker-inspect returned an invalid StartedAt value",
                        "value": stdout,
                        "stdout": stdout,
                        "stderr": stderr,
                        "err": format!("{}", e),
                    })),
                )
            }
            Ok(v) => DateTime::<Utc>::from(v),
        };

        let uptime = Utc::now() - started_at;

        if uptime < Duration::seconds(90) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "TOO_FRESH",
                    "info": "container was just started",
                    "stdout": stdout,
                    "stderr": stderr,
                    "started_at": started_at.to_rfc3339(),
                    "uptime": uptime.num_seconds(),
                })),
            );
        }

        out_uptime = uptime.num_seconds();
        out_started_at = started_at.to_rfc3339();
    }

    return (
        StatusCode::OK,
        Json(json!({
                "container_name": container_name,
                "status": out_status,
                "uptime": out_uptime,
                "started_at": out_started_at,
            }
        )),
    );
}

async fn check_service(Path(name): Path<String>, req: Request<Body>, args: Args) -> impl IntoResponse {
    if let Some(r) = auth(req, args).await {
        return r
    }

    let service_name = name.as_str();

    let cmdargs = vec!(
        "show", 
        service_name, 
        "--property=ActiveState",
        "--property=ActiveEnterTimestamp",
        "--property=Type",
        "--property=MainPID",
        "--property=Id",
    );
    

    let (mut cmd, cmdstr) = cmd("systemctl", cmdargs);

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let response = cmd.execute_output();

    let output = match response {
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "EXEC_FAILED",
                    "info": "Command::execute_output() returned an error",
                    "err": format!("{}", e)
                })),
            )
        }
        Ok(v) => v,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    if let Some(exit_code) = output.status.code() {
        if exit_code != 0 {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "EXIT_CODE",
                    "info": format!("systemctl-show returned exit code {}", exit_code),
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            );
        }
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "cmd": cmdstr,
                "error": "INTERRUPTED",
                "info": "systemctl-show was interrupted",
                "stdout": stdout,
                "stderr": stderr,
            })),
        );
    }

    if !stderr.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "cmd": cmdstr,
                "error": "STDERR",
                "info": "systemctl-show returned an error",
                "stdout": stdout,
                "stderr": stderr,
            })),
        );
    }

    let mut svc_active_state = "".to_owned();
    let mut svc_active_enter_timestamp = "".to_owned();
    let mut svc_type = "".to_owned();
    let mut svc_main_pid = "".to_owned();
    let mut svc_id = "".to_owned();

    for pline in stdout.lines() {
        match pline.split_once('=') {
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "SYSCTL_PARSE",
                        "info": "failed to parse systemctl-show output",
                        "line": pline,
                        "stdout": stdout,
                        "stderr": stderr,
                    })),
                )
            }
            Some(("ActiveState", v)) => svc_active_state = v.to_owned(),
            Some(("ActiveEnterTimestamp", v)) => svc_active_enter_timestamp = v.to_owned(),
            Some(("Type", v)) => svc_type = v.to_owned(),
            Some(("MainPID", v)) => svc_main_pid = v.to_owned(),
            Some(("Id", v)) => svc_id = v.to_owned(),
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "SYSCTL_PARSE",
                        "info": "failed to parse systemctl-show output",
                        "line": pline,
                        "stdout": stdout,
                        "stderr": stderr,
                    })),
                )
            }
        }
    }

    if svc_active_state != "active" {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "cmd": cmdstr,
                "error": "NOT_ACTIVE",
                "info": "service is not running",
                "stdout": stdout,
                "stderr": stderr,
                "active_state": svc_active_state,
            })),
        );
    }

    let active_enter = match NaiveDateTime::parse_from_str(&svc_active_enter_timestamp, "%a %Y-%m-%d %H:%M:%S %Z") {
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "ACTIVEENTER_PARSE",
                    "info": "systemctl-show returned an invalid ActiveEnterTimestamp value",
                    "value": svc_active_enter_timestamp,
                    "stdout": stdout,
                    "stderr": stderr,
                    "err": format!("{}", e),
                })),
            )
        }
        Ok(v) => match Local.from_local_datetime(&v) {
            chrono::LocalResult::None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "ACTIVEENTER_PARSE",
                        "info": "systemctl-show returned an unparseable ActiveEnterTimestamp value",
                        "value": svc_active_enter_timestamp,
                        "stdout": stdout,
                        "stderr": stderr,
                    })),
                )
            }
            chrono::LocalResult::Ambiguous(opt1, opt2) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmdstr,
                        "error": "ACTIVEENTER_PARSE",
                        "info": "systemctl-show returned an ambiguous ActiveEnterTimestamp value",
                        "value": svc_active_enter_timestamp,
                        "stdout": stdout,
                        "stderr": stderr,
                        "opt1": opt1.to_rfc3339(),
                        "opt2": opt2.to_rfc3339(),
                    })),
                )
            }
            chrono::LocalResult::Single(v) => DateTime::<Utc>::from(v),
        },
    };

    let uptime = Utc::now() - active_enter;

    if uptime < Duration::seconds(90) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "cmd": cmdstr,
                "error": "TOO_FRESH",
                "info": "service was just started",
                "stdout": stdout,
                "stderr": stderr,
                "started_at": active_enter.to_rfc3339(),
                "uptime": uptime.num_seconds(),
            })),
        );
    }

    return (
        StatusCode::OK,
        Json(json!({
                "service_name": service_name,
                "svc_active_state": svc_active_state,
                "svc_active_enter_timestamp": svc_active_enter_timestamp,
                "svc_type": svc_type,
                "svc_main_pid": svc_main_pid,
                "svc_id": svc_id,
                "uptime": uptime.num_seconds(),
                "started_at": active_enter.to_rfc3339(),
            }
        )),
    );
}

async fn check_source_rcon(Path(name): Path<String>, req: Request<Body>, args: Args) -> impl IntoResponse {
    if let Some(r) = auth(req, args.clone()).await {
        return r
    }

    let server_name = name.as_str();

    let address = args.source_rcon_address;
    let pw = args.source_rcon_pass;

    let remote_addr: SocketAddr = match address.parse() {
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "remote_addr": address,
                    "error": "ADDR_PARSE_ERR",
                    "info": "failed to parse rcon address",
                    "err": format!("{}", e),
                })),
            )
        }
        Ok(v) => v,
    };

    let local_addr_str = if remote_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let local_addr: SocketAddr = local_addr_str.parse().unwrap();

    let socket = match UdpSocket::bind(local_addr).await {
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "remote_addr": address,
                    "local_addr": local_addr_str,
                    "error": "BIND_ERR",
                    "info": "failed to bind local address",
                    "err": format!("{}", e),
                })),
            )
        }
        Ok(v) => v,
    };

    if let Err(e) = socket.connect(&remote_addr).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "remote_addr": address,
                "local_addr": local_addr_str,
                "error": "CONN_ERR",
                "info": "failed to connect to remote",
                "err": format!("{}", e),
            })),
        )
    }

    let challenge_nonce: String;

    {
        let cmd_challenge = "####challenge rcon#";
        let mut data_challenge = cmd_challenge.as_bytes().to_vec();
        let data_challenge_len = data_challenge.len();
        data_challenge[0] = 255;
        data_challenge[1] = 255;
        data_challenge[2] = 255;
        data_challenge[3] = 255;
        data_challenge[data_challenge_len - 1] = 0;

        if let Err(e) = socket.send(&data_challenge).await {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmd_challenge,
                    "remote_addr": address,
                    "local_addr": local_addr_str,
                    "error": "CHALLENGE_ERR",
                    "info": "failed to send rcon challenge",
                    "err": format!("{}", e),
                })),
            )
        }

        let mut response_challenge_bin = vec![0u8; 10_000];
        let response_challenge_len = match socket.recv(&mut response_challenge_bin).await {
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "cmd": cmd_challenge,
                        "remote_addr": address,
                        "local_addr": local_addr_str,
                        "error": "CHALLENGE_ERR",
                        "info": "failed to receive rcon challenge response",
                        "err": format!("{}", e),
                    })),
                )
            }
            Ok(v) => v,
        };

        let response_challenge = String::from_utf8_lossy(&response_challenge_bin[..response_challenge_len]).into_owned();

        lazy_static! {
            static ref REX_CHALLENGE_RESPONSE: Regex = Regex::new(".*challenge rcon ([0-9]+).*").unwrap();
        }

        challenge_nonce = match REX_CHALLENGE_RESPONSE.captures(&response_challenge) {
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "cmd": cmd_challenge,
                        "remote_addr": address,
                        "local_addr": local_addr_str,
                        "error": "NONCE_ERR",
                        "info": "failed to parse rcon challenge response",
                        "response": response_challenge,
                    })),
                )
            }
            Some(v) => match v.get(1) {
                None => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "cmd": cmd_challenge,
                            "remote_addr": address,
                            "local_addr": local_addr_str,
                            "error": "NONCE_GRP_ERR",
                            "info": "failed to parse rcon challenge response",
                            "response": response_challenge,
                        })),
                    )
                }
                Some(v) => v.as_str().to_owned(),
            },
        };
    }

    let cmd_status = format!(r#"####rcon "{}" {} {}#"#, challenge_nonce, pw, "status");
    let mut data_status = cmd_status.as_bytes().to_vec();
    let data_status_len = data_status.len();
    data_status[0] = 255;
    data_status[1] = 255;
    data_status[2] = 255;
    data_status[3] = 255;
    data_status[data_status_len - 1] = 0;

    if let Err(e) = socket.send(&data_status).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "cmd": cmd_status,
                "remote_addr": address,
                "local_addr": local_addr_str,
                "error": "CMD_ERR",
                "info": "failed to send rcon command `status`",
                "err": format!("{}", e),
            })),
        )
    }

    let mut response_status_bin = vec![0u8; 10_000];
    if let Err(e) = socket.recv(&mut response_status_bin).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "cmd": cmd_status,
                "remote_addr": address,
                "local_addr": local_addr_str,
                "error": "CMD_RECV_ERR",
                "info": "failed to receive rcon response",
                "err": format!("{}", e),
            })),
        )
    }

    let idx = match response_status_bin.iter().position(|&p| p == 0) {
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "cmd": cmd_status,
                    "remote_addr": address,
                    "local_addr": local_addr_str,
                    "error": "CMD_RESP_READ",
                    "bin": response_status_bin,
                    "info": "failed to find end of rcon response",
                })),
            )
        }
        Some(v) => v,
    };

    let response_status = String::from_utf8_lossy(&response_status_bin[5..idx]).into_owned();

    let mut srv_hostname = "".to_owned();
    let mut srv_version = "".to_owned();
    let mut srv_ip = "".to_owned();
    let mut srv_map = "".to_owned();
    let mut srv_players = "".to_owned();

    for pline in response_status.lines() {
        if let Some((k, v)) = pline.split_once(':') {
            match (k.trim(), v.trim()) {
                ("hostname", v) => srv_hostname = v.to_owned(),
                ("version", v) => srv_version = v.to_owned(),
                ("tcp/ip", v) => srv_ip = v.to_owned(),
                ("map", v) => srv_map = v.to_owned(),
                ("players", v) => srv_players = v.trim().to_owned(),
                _ => {}
            }
        }
    }

    if srv_hostname != server_name {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "SERVERNAME_MISMATCH",
                "info": "Server returned wrong hostname",
                "name_should": server_name,
                "name_actual": srv_hostname,
            })),
        );
    }

    return (
        StatusCode::OK,
        Json(json!({
                "server_hostname": srv_hostname,
                "server_version": srv_version,
                "server_ip": srv_ip,
                "server_map": srv_map,
                "server_players": srv_players,
            }
        )),
    );
}

async fn auth(req: Request<Body>, args: Args) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if args.auth_user.is_empty() && args.auth_pass.is_empty() {
        return None
    }

    let auth_header = match req.headers().get(axum::http::header::AUTHORIZATION).and_then(|header| header.to_str().ok()) {
            None => return Some((StatusCode::UNAUTHORIZED, Json(json!({"error":"NO_AUTH", "info": "No auth header supplied"})))),
            Some(v) => v,
        };

    let expected = format!("Basic {}", base64::encode(format!("{}:{}", args.auth_user, args.auth_pass)));

    if auth_header != expected {
        return Some((StatusCode::UNAUTHORIZED, Json(json!({"error":"AUTH_FAILURE", "info": "Failed to validate auth header"}))));
    }

    return None
}

fn cmd(f: &str, args: Vec<&str>) -> (::std::process::Command, String) {
    let mut cmdstr = f.to_owned();

    let mut command = ::std::process::Command::new(f);
    for a in args {
        command.arg(a);
        cmdstr += format!(" \"{}\"", a).as_str();
    }

    return (command, cmdstr);
}
