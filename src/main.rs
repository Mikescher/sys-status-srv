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

use chrono::{prelude::*, Duration};

use std::str::FromStr;

use execute::Execute;

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

    let mut app = Router::new();
    app = app.route("/", get(root));
    app = app.route("/rcon", get(check_rcon));
    app = app.route("/service/:name", get(check_service));
    app = app.route("/docker/:name", get(check_docker));
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

async fn check_docker(Path(name): Path<String>) -> impl IntoResponse {
    let container_name = name.as_str();

    let out_status: String;
    let out_uptime: i64;
    let out_started_at: String;

    {
        let (mut cmd, cmdstr) = cmd("docker", vec!("inspect", "-f", "{{.State.Status}}", container_name));
    
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

        if stderr != "" {
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
        let (mut cmd, cmdstr) = cmd("docker", vec!("inspect", "-f", "{{.State.StartedAt}}", container_name));
    
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

        if stderr != "" {
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
            Err(e) => 
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
            ),
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
    )))

}

async fn check_service(Path(name): Path<String>) -> impl IntoResponse {
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

    if stderr != "" {
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
            None => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "SYSCTL_PARSE",
                    "info": "failed to parse systemctl-show output",
                    "line": pline,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            ),
            Some(("ActiveState", v)) => svc_active_state = v.to_owned(),
            Some(("ActiveEnterTimestamp", v)) => svc_active_enter_timestamp = v.to_owned(),
            Some(("Type", v)) => svc_type = v.to_owned(),
            Some(("MainPID", v)) => svc_main_pid = v.to_owned(),
            Some(("Id", v)) => svc_id = v.to_owned(),
            _ => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "SYSCTL_PARSE",
                    "info": "failed to parse systemctl-show output",
                    "line": pline,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            ),
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
        Err(e) => 
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
        ),
        Ok(v) => match Local.from_local_datetime(&v) {
            chrono::LocalResult::None => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "cmd": cmdstr,
                    "error": "ACTIVEENTER_PARSE",
                    "info": "systemctl-show returned an unparseable ActiveEnterTimestamp value",
                    "value": svc_active_enter_timestamp,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            ),
            chrono::LocalResult::Ambiguous(opt1, opt2) => return (
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
            ),
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
    )))

}

async fn check_rcon() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "a": "b" })))
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