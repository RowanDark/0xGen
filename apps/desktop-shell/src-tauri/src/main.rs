#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{collections::HashMap, sync::Mutex, time::Duration};

use chrono::{DateTime, Utc};
use futures::{
    future::{AbortHandle, Abortable},
    StreamExt,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
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

fn build_stream_key(prefix: &str, id: &str) -> String {
    format!("{prefix}:{id}")
}

struct GlyphApi {
    client: reqwest::Client,
    base_url: String,
    streams: Mutex<HashMap<String, StreamController>>,
}

impl GlyphApi {
    fn new() -> Self {
        let base_url =
            std::env::var("GLYPH_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8713".to_string());
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
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardMetrics {
    failures: f64,
    queue_depth: f64,
    avg_latency_ms: f64,
    cases_found: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FlowEventPayload {
    id: String,
    sequence: u64,
    #[serde(rename = "type")]
    kind: String,
    timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_body_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_body_captured: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_redacted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlowPage {
    items: Vec<FlowEventPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct FlowFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    statuses: Vec<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    plugin_tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResendFlowResponse {
    flow_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug)]
struct MetricSample {
    name: String,
    labels: HashMap<String, String>,
    value: f64,
}

fn parse_metric_identifier(identifier: &str) -> Option<(String, HashMap<String, String>)> {
    if let Some(start) = identifier.find('{') {
        let end = identifier.rfind('}')?;
        let name = identifier[..start].to_string();
        let mut labels = HashMap::new();
        let inner = &identifier[start + 1..end];
        for pair in inner.split(',') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, '=');
            let key = parts.next()?.trim();
            let raw_value = parts.next()?.trim();
            let value = raw_value
                .trim_matches('"')
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            labels.insert(key.to_string(), value);
        }
        Some((name, labels))
    } else {
        Some((identifier.to_string(), HashMap::new()))
    }
}

fn parse_metric_line(line: &str) -> Option<MetricSample> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let metric_part = parts.next()?;
    let value_str = parts.next()?;
    // Ignore optional timestamp token if present.
    let _timestamp = parts.next();
    let value: f64 = value_str.parse().ok()?;
    let (name, labels) = parse_metric_identifier(metric_part)?;

    Some(MetricSample {
        name,
        labels,
        value,
    })
}

fn parse_metrics(body: &str) -> Vec<MetricSample> {
    body.lines().filter_map(parse_metric_line).collect()
}

fn sum_metric(samples: &[MetricSample], name: &str) -> f64 {
    samples
        .iter()
        .filter(|sample| sample.name == name)
        .map(|sample| sample.value)
        .sum()
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
async fn start_run(
    api: State<'_, GlyphApi>,
    name: String,
    template: Option<String>,
) -> Result<StartRunResponse, String> {
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

    response
        .json::<StartRunResponse>()
        .await
        .map_err(|err| err.to_string())
}

fn emit_run_event(window: &Window, run_id: &str, event: RunEvent) -> Result<(), ApiError> {
    let event_name = format!("runs:{}:events", run_id);
    window
        .emit(event_name, Some(event))
        .map_err(|_| ApiError::WindowMissing)
}

fn emit_flow_event(window: &Window, stream_id: &str, event: FlowEventPayload) -> Result<(), ApiError> {
    let event_name = format!("flows:{}:events", stream_id);
    window
        .emit(event_name, Some(event))
        .map_err(|_| ApiError::WindowMissing)
}

#[tauri::command]
async fn fetch_metrics(api: State<'_, GlyphApi>) -> Result<DashboardMetrics, String> {
    let url = api.endpoint("metrics");
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

    let body = response.text().await.map_err(|err| err.to_string())?;
    let samples = parse_metrics(&body);

    let failures = sum_metric(&samples, "glyph_rpc_errors_total");
    let queue_depth = sum_metric(&samples, "glyph_plugin_queue_length");
    let latency_sum = sum_metric(&samples, "glyph_plugin_event_duration_seconds_sum");
    let latency_count = sum_metric(&samples, "glyph_plugin_event_duration_seconds_count");
    let avg_latency_ms = if latency_count > 0.0 {
        (latency_sum / latency_count) * 1000.0
    } else {
        0.0
    };

    let mut cases_found = 0.0;
    for name in [
        "glyph_cases_total",
        "glyph_case_reports_total",
        "glyph_case_count",
        "glyph_cases_emitted_total",
        "glyph_case_findings_total",
    ] {
        let value = sum_metric(&samples, name);
        if value > 0.0 {
            cases_found = value;
            break;
        }
        cases_found = cases_found.max(value);
    }

    Ok(DashboardMetrics {
        failures,
        queue_depth,
        avg_latency_ms,
        cases_found,
    })
}

#[tauri::command]
async fn list_flows(
    api: State<'_, GlyphApi>,
    cursor: Option<String>,
    limit: Option<u32>,
    filters: Option<FlowFilters>,
) -> Result<FlowPage, String> {
    let mut url = Url::parse(&api.endpoint("flows")).map_err(|err| err.to_string())?;
    let filters = filters.unwrap_or_default();

    {
        let mut pairs = url.query_pairs_mut();
        if let Some(cursor) = cursor {
            let trimmed = cursor.trim();
            if !trimmed.is_empty() {
                pairs.append_pair("cursor", trimmed);
            }
        }
        if let Some(limit) = limit {
            pairs.append_pair("limit", &limit.to_string());
        }
        if let Some(search) = filters
            .search
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("search", search);
        }
        for method in filters
            .methods
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("method", method);
        }
        for status in &filters.statuses {
            pairs.append_pair("status", &status.to_string());
        }
        for domain in filters
            .domains
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("domain", domain);
        }
        for scope in filters
            .scope
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("scope", scope);
        }
        for tag in filters
            .tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("tag", tag);
        }
        for plugin_tag in filters
            .plugin_tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("pluginTag", plugin_tag);
        }
    }

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
        .json::<FlowPage>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn stream_events(
    app: tauri::AppHandle,
    api: State<'_, GlyphApi>,
    run_id: String,
) -> Result<(), String> {
    let window = app
        .get_window("main")
        .ok_or_else(|| ApiError::WindowMissing.to_string())?;

    let url = api.endpoint(&format!("runs/{}/events", run_id));
    let client = api.client.clone();
    let window_clone = window.clone();
    let run_id_clone = run_id.clone();
    let stream_key = build_stream_key("run", &run_id);

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
                        if let Err(err) =
                            emit_run_event(&window_clone, &run_id_clone, event.clone())
                        {
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
    if let Some(existing) = guard.insert(
        stream_key,
        StreamController {
            abort: abort_handle,
        },
    ) {
        existing.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stop_stream(api: State<'_, GlyphApi>, run_id: String) -> Result<(), String> {
    let key = build_stream_key("run", &run_id);
    if let Some(controller) = api
        .streams
        .lock()
        .map_err(|err| err.to_string())?
        .remove(&key)
    {
        controller.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stream_flows(
    app: tauri::AppHandle,
    api: State<'_, GlyphApi>,
    stream_id: String,
    filters: Option<FlowFilters>,
) -> Result<(), String> {
    let window = app
        .get_window("main")
        .ok_or_else(|| ApiError::WindowMissing.to_string())?;

    let mut url = Url::parse(&api.endpoint("flows/events")).map_err(|err| err.to_string())?;
    let filters = filters.unwrap_or_default();
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(search) = filters
            .search
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("search", search);
        }
        for method in filters
            .methods
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("method", method);
        }
        for status in &filters.statuses {
            pairs.append_pair("status", &status.to_string());
        }
        for domain in filters
            .domains
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("domain", domain);
        }
        for scope in filters
            .scope
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("scope", scope);
        }
        for tag in filters
            .tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("tag", tag);
        }
        for plugin_tag in filters
            .plugin_tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("pluginTag", plugin_tag);
        }
    }

    let client = api.client.clone();
    let window_clone = window.clone();
    let stream_id_clone = stream_id.clone();
    let stream_key = build_stream_key("flow", &stream_id);

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

                match from_str::<FlowEventPayload>(&payload) {
                    Ok(event) => {
                        if let Err(err) =
                            emit_flow_event(&window_clone, &stream_id_clone, event.clone())
                        {
                            eprintln!("Failed to emit flow event: {err}");
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to parse flow event payload: {err}");
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
    if let Some(existing) = guard.insert(
        stream_key,
        StreamController {
            abort: abort_handle,
        },
    ) {
        existing.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stop_flow_stream(api: State<'_, GlyphApi>, stream_id: String) -> Result<(), String> {
    let key = build_stream_key("flow", &stream_id);
    if let Some(controller) = api
        .streams
        .lock()
        .map_err(|err| err.to_string())?
        .remove(&key)
    {
        controller.stop();
    }

    Ok(())
}

#[tauri::command]
async fn resend_flow(
    api: State<'_, GlyphApi>,
    flow_id: String,
    message: String,
) -> Result<ResendFlowResponse, String> {
    let url = api.endpoint(&format!("flows/{}/resend", flow_id));
    let payload = json!({ "message": message });
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

    response
        .json::<ResendFlowResponse>()
        .await
        .map_err(|err| err.to_string())
}

fn configure_devtools(window: &Window) {
    let allow_devtools =
        std::env::var("GLYPH_ENABLE_DEVTOOLS").map(|v| v == "1" || v.eq_ignore_ascii_case("true"));
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
        .invoke_handler(tauri::generate_handler![
            list_runs,
            start_run,
            list_flows,
            stream_events,
            stop_stream,
            stream_flows,
            stop_flow_stream,
            resend_flow,
            fetch_metrics
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
