#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    collections::HashMap,
    sync::Mutex,
    time::Duration,
};

use chrono::{DateTime, Utc};
use futures::{future::{AbortHandle, Abortable}, StreamExt};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::from_str;
use tauri::{async_runtime, Manager, State, Window};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
enum ApiError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("unexpected response ({status}): {body}")]
    UnexpectedResponse { status: StatusCode, body: String },
    #[error("window not available")]
    WindowMissing,
}

#[derive(Clone)]
struct StreamController {
    abort: AbortHandle,
}

impl StreamController {
    fn stop(self) {
        self.abort.abort();
    }
}

struct GlyphApi {
    client: reqwest::Client,
    base_url: String,
    streams: Mutex<HashMap<String, StreamController>>,
}

impl GlyphApi {
    fn new() -> Self {
        let base_url = std::env::var("GLYPH_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8713".to_string());
        let parsed = Url::parse(&base_url).expect("invalid GLYPH_API_URL");
        match parsed.host_str() {
            Some("127.0.0.1") | Some("localhost") | Some("::1") => {}
            other => panic!("GLYPH_API_URL must point to localhost, got {:?}", other),
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            base_url,
            streams: Mutex::new(HashMap::new()),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    id: String,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartRunRequest {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartRunResponse {
    id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RunEvent {
    #[serde(rename = "type")]
    kind: String,
    timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    payload: Value,
}

#[tauri::command]
async fn list_runs(api: State<'_, GlyphApi>) -> Result<Vec<Run>, String> {
    let url = api.endpoint("runs");
    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<Vec<Run>>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn start_run(api: State<'_, GlyphApi>, name: String, template: Option<String>) -> Result<StartRunResponse, String> {
    let url = api.endpoint("runs");
    let payload = StartRunRequest { name, template };
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response.json::<StartRunResponse>().await.map_err(|err| err.to_string())
}

fn emit_run_event(window: &Window, run_id: &str, event: RunEvent) -> Result<(), ApiError> {
    let event_name = format!("runs:{}:events", run_id);
    window
        .emit(event_name, Some(event))
        .map_err(|_| ApiError::WindowMissing)
}

#[tauri::command]
async fn stream_events(app: tauri::AppHandle, api: State<'_, GlyphApi>, run_id: String) -> Result<(), String> {
    let window = app
        .get_window("main")
        .ok_or_else(|| ApiError::WindowMissing.to_string())?;

    let url = api.endpoint(&format!("runs/{}/events", run_id));
    let client = api.client.clone();
    let window_clone = window.clone();
    let run_id_clone = run_id.clone();

    let (abort_handle, abort_reg) = futures::future::AbortHandle::new_pair();

    let forward = async move {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnexpectedResponse { status, body });
        }

        let mut buffer = String::new();
        let mut byte_stream = response.bytes_stream();

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(index) = buffer.find('\n') {
                let line = buffer[..index].trim().to_string();
                buffer = buffer[index + 1..].to_string();

                if line.is_empty() {
                    continue;
                }

                let payload = if let Some(data) = line.strip_prefix("data:") {
                    data.trim().to_string()
                } else {
                    line
                };

                match from_str::<RunEvent>(&payload) {
                    Ok(event) => {
                        if let Err(err) = emit_run_event(&window_clone, &run_id_clone, event.clone()) {
                            eprintln!("Failed to emit event: {err}");
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to parse event payload: {err}");
                    }
                }
            }
        }

        Ok::<(), ApiError>(())
    };

    let abortable = Abortable::new(forward, abort_reg);

    async_runtime::spawn(async move {
        match abortable.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("Stream error: {err}"),
            Err(_) => {}
        }
    });

    let mut guard = api.streams.lock().map_err(|err| err.to_string())?;
    if let Some(existing) = guard.insert(run_id, StreamController { abort: abort_handle }) {
        existing.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stop_stream(api: State<'_, GlyphApi>, run_id: String) -> Result<(), String> {
    if let Some(controller) = api.streams.lock().map_err(|err| err.to_string())?.remove(&run_id) {
        controller.stop();
    }

    Ok(())
}

fn configure_devtools(window: &Window) {
    let allow_devtools = std::env::var("GLYPH_ENABLE_DEVTOOLS").map(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if let Ok(true) = allow_devtools {
        let _ = window.open_devtools();
    }
}

fn main() {
    tauri::Builder::default()
        .manage(GlyphApi::new())
        .setup(|app| {
            if let Some(window) = app.get_window("main") {
                configure_devtools(&window);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![list_runs, start_run, stream_events, stop_stream])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
