// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::net::TcpListener;

use s3chaos::fault::console::{ConsoleSnapshot, build_console_snapshot};
use s3chaos::workflow::report::{
    RunFilter, RunPage, RunReport, list_runs_filtered, read_run_report,
};

const MAX_ARTIFACT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_DIRECTORY_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct ConsoleServerState {
    default_root: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct ArtifactReadLimits {
    max_file_bytes: u64,
    max_directory_entries: usize,
}

impl Default for ArtifactReadLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_ARTIFACT_FILE_BYTES,
            max_directory_entries: MAX_ARTIFACT_DIRECTORY_ENTRIES,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConsoleQuery {
    root: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunsQuery {
    root: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
    #[serde(flatten)]
    filter: RunFilter,
}

#[derive(Debug, Deserialize)]
struct ArtifactRequestQuery {
    root: Option<String>,
    path: String,
    download: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactQuery {
    root: Option<String>,
    path: String,
}

pub async fn serve_console(default_root: impl Into<PathBuf>, addr: SocketAddr) -> Result<()> {
    let state = ConsoleServerState {
        default_root: default_root.into(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/api/artifact", get(artifact))
        .route("/api/console", get(console_snapshot))
        .route("/api/runs", get(run_history))
        .route("/api/report", get(run_report))
        .with_state(state.clone());

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind console server on {addr}"))?;
    let local_addr = listener
        .local_addr()
        .context("read console server address")?;
    eprintln!("s3chaos console: http://{local_addr}/");
    eprintln!("default artifact root: {}", state.default_root.display());
    axum::serve(listener, app)
        .await
        .context("serve s3chaos console")
}

async fn artifact(
    State(state): State<ConsoleServerState>,
    Query(query): Query<ArtifactRequestQuery>,
) -> Response {
    let download = download_requested(query.download.as_deref());
    let download_name = artifact_download_filename(&query.path);
    let artifact_query = ArtifactQuery {
        root: query.root,
        path: query.path,
    };

    match read_artifact(&state, artifact_query) {
        Ok(content) => {
            let mut response = (
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                content,
            )
                .into_response();
            if download {
                response.headers_mut().insert(
                    header::CONTENT_DISPOSITION,
                    attachment_header_value(&download_name),
                );
            }
            response
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

fn read_artifact(state: &ConsoleServerState, query: ArtifactQuery) -> Result<String> {
    read_artifact_with_limits(state, query, ArtifactReadLimits::default())
}

fn read_artifact_with_limits(
    state: &ConsoleServerState,
    query: ArtifactQuery,
    limits: ArtifactReadLimits,
) -> Result<String> {
    let (default_root, root) = resolve_request_roots(state, query.root)?;
    let requested = PathBuf::from(&query.path);
    if requested.is_absolute() {
        bail!("artifact path must be relative: {}", requested.display());
    }

    let path = root.join(requested);
    let path = fs::canonicalize(&path)
        .with_context(|| format!("canonicalize artifact path {}", path.display()))?;

    ensure_within_default_root(&path, &default_root, "artifact path")?;

    if path.is_dir() {
        return read_artifact_directory(&path, limits.max_directory_entries);
    }

    read_artifact_file(&path, limits.max_file_bytes)
}

fn download_requested(value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .is_some_and(|value| matches!(value, "1" | "true" | "yes" | "download"))
}

fn artifact_download_filename(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("artifact.txt");
    let sanitized = file_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "artifact.txt".to_string()
    } else {
        sanitized
    }
}

fn attachment_header_value(file_name: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("attachment; filename=\"{file_name}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

fn read_artifact_directory(path: &Path, max_entries: usize) -> Result<String> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(path).with_context(|| format!("read artifact directory {}", path.display()))?
    {
        let entry = entry
            .with_context(|| format!("read artifact directory entry under {}", path.display()))?;
        if entries.len() >= max_entries {
            bail!(
                "artifact directory {} exceeds {max_entries} entry limit; refine the artifact path",
                path.display()
            );
        }
        entries.push(entry.file_name().to_string_lossy().into_owned());
    }
    entries.sort();
    Ok(entries.join("\n"))
}

fn read_artifact_file(path: &Path, max_bytes: u64) -> Result<String> {
    let metadata =
        fs::metadata(path).with_context(|| format!("inspect artifact file {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "artifact path {} is not a regular file",
        path.display()
    );

    if metadata.len() > max_bytes {
        return read_artifact_tail(path, metadata.len(), max_bytes);
    }

    read_artifact_text_with_limit(path, max_bytes)
}

fn read_artifact_text_with_limit(path: &Path, max_bytes: u64) -> Result<String> {
    let file =
        fs::File::open(path).with_context(|| format!("open artifact file {}", path.display()))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(usize::MAX as u64) as usize);
    let mut reader = file.take(max_bytes.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("read artifact file {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        let len = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(bytes.len() as u64);
        return read_artifact_tail(path, len, max_bytes);
    }

    String::from_utf8(bytes).with_context(|| format!("decode artifact file {}", path.display()))
}

fn read_artifact_tail(path: &Path, file_len: u64, max_bytes: u64) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open artifact file {}", path.display()))?;
    let start = file_len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seek artifact file {}", path.display()))?;

    let mut bytes = Vec::with_capacity(max_bytes.min(usize::MAX as u64) as usize);
    let mut reader = file.take(max_bytes);
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("read artifact tail {}", path.display()))?;
    let tail = String::from_utf8_lossy(&bytes);
    Ok(format!(
        "[s3chaos: artifact truncated; showing last {} of {file_len} bytes]\n{tail}",
        bytes.len()
    ))
}

fn resolve_request_roots(
    state: &ConsoleServerState,
    root: Option<String>,
) -> Result<(PathBuf, PathBuf)> {
    let default_root = fs::canonicalize(&state.default_root).with_context(|| {
        format!(
            "canonicalize default artifact root {}",
            state.default_root.display()
        )
    })?;

    let Some(root) = root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok((default_root.clone(), default_root));
    };

    let requested_root = PathBuf::from(root);
    let requested_root = if requested_root.is_absolute() {
        requested_root
    } else {
        default_root.join(requested_root)
    };
    let requested_root = fs::canonicalize(&requested_root).with_context(|| {
        format!(
            "canonicalize requested artifact root {}",
            requested_root.display()
        )
    })?;
    ensure_within_default_root(&requested_root, &default_root, "requested artifact root")?;

    Ok((default_root, requested_root))
}

fn ensure_within_default_root(path: &Path, default_root: &Path, label: &str) -> Result<()> {
    if !path.starts_with(default_root) {
        bail!(
            "{label} {} is outside default artifact root {}",
            path.display(),
            default_root.display()
        );
    }
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../../console/index.html"))
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../console/app.js"),
    )
        .into_response()
}

async fn styles_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../console/styles.css"),
    )
        .into_response()
}

async fn console_snapshot(
    State(state): State<ConsoleServerState>,
    Query(query): Query<ConsoleQuery>,
) -> Response {
    match console_snapshot_for_query(&state, query) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": error.to_string(),
                "root": state.default_root.display().to_string(),
            })),
        )
            .into_response(),
    }
}

async fn run_history(
    State(state): State<ConsoleServerState>,
    Query(query): Query<RunsQuery>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || run_history_for_query(&state, query))
        .await
        .context("read run history")
        .and_then(|result| result);
    report_response(result)
}

async fn run_report(
    State(state): State<ConsoleServerState>,
    Query(query): Query<ConsoleQuery>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || run_report_for_query(&state, query))
        .await
        .context("read run report")
        .and_then(|result| result);
    report_response(result)
}

fn report_response<T: serde::Serialize>(result: Result<T>) -> Response {
    match result {
        Ok(report) => Json(report).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

fn run_history_for_query(state: &ConsoleServerState, query: RunsQuery) -> Result<RunPage> {
    let (_, root) = resolve_request_roots(state, query.root)?;
    list_runs_filtered(
        root,
        &query.filter,
        query.offset.unwrap_or(0),
        query.limit.unwrap_or(20),
    )
}

fn run_report_for_query(state: &ConsoleServerState, query: ConsoleQuery) -> Result<RunReport> {
    let (_, root) = resolve_request_roots(state, query.root)?;
    read_run_report(root)
}

fn console_snapshot_for_query(
    state: &ConsoleServerState,
    query: ConsoleQuery,
) -> Result<ConsoleSnapshot> {
    let (_, root) = resolve_request_roots(state, query.root)?;
    build_console_snapshot(&root)
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactQuery, ArtifactReadLimits, ArtifactRequestQuery, ConsoleQuery, ConsoleServerState,
        RunsQuery, artifact, artifact_download_filename, console_snapshot_for_query, read_artifact,
        read_artifact_with_limits, run_history_for_query, run_report_for_query,
    };
    use axum::{
        extract::{Query, State},
        http::{StatusCode, header},
    };
    use std::{fs, path::Path};

    fn state(default_root: &Path) -> ConsoleServerState {
        ConsoleServerState {
            default_root: default_root.to_path_buf(),
        }
    }

    #[test]
    fn history_query_decodes_pagination_and_filters() {
        let query: RunsQuery = serde_urlencoded::from_str(
            "offset=20&limit=10&kind=protocol&result=failed&since=2026-11-01",
        )
        .unwrap();
        assert_eq!(query.offset, Some(20));
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.filter.kind.as_deref(), Some("protocol"));
        assert_eq!(query.filter.since.as_deref(), Some("2026-11-01"));
    }

    #[test]
    fn history_and_report_reject_roots_outside_default_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let requested = Some(outside.path().display().to_string());
        assert!(
            run_report_for_query(
                &state(root.path()),
                ConsoleQuery {
                    root: requested.clone()
                }
            )
            .is_err()
        );
        assert!(
            run_history_for_query(
                &state(root.path()),
                RunsQuery {
                    root: requested,
                    offset: None,
                    limit: None,
                    filter: Default::default(),
                }
            )
            .is_err()
        );
    }

    #[test]
    fn console_snapshot_rejects_root_outside_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");

        let error = console_snapshot_for_query(
            &state(dir.path()),
            ConsoleQuery {
                root: Some("/".to_string()),
            },
        )
        .expect_err("root outside default root");

        let message = error.to_string();
        assert!(message.contains("requested artifact root"));
        assert!(message.contains("outside default artifact root"));
    }

    #[test]
    fn console_snapshot_without_root_uses_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");

        let snapshot = console_snapshot_for_query(&state(dir.path()), ConsoleQuery { root: None })
            .expect("snapshot");

        assert_eq!(
            snapshot.artifact_root,
            fs::canonicalize(dir.path())
                .expect("canonical root")
                .display()
                .to_string()
        );
    }

    #[test]
    fn console_snapshot_relative_root_is_resolved_under_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let child = dir.path().join("suite");
        fs::create_dir_all(&child).expect("child root");

        let snapshot = console_snapshot_for_query(
            &state(dir.path()),
            ConsoleQuery {
                root: Some("suite".to_string()),
            },
        )
        .expect("snapshot");

        assert_eq!(
            snapshot.artifact_root,
            fs::canonicalize(child)
                .expect("canonical child")
                .display()
                .to_string()
        );
    }

    #[test]
    fn artifact_rejects_root_outside_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("ok.txt"), "ok").expect("artifact");

        let error = read_artifact(
            &state(dir.path()),
            ArtifactQuery {
                root: Some("/".to_string()),
                path: "ok.txt".to_string(),
            },
        )
        .expect_err("root outside default root");

        let message = error.to_string();
        assert!(message.contains("requested artifact root"));
        assert!(message.contains("outside default artifact root"));
    }

    #[test]
    fn artifact_rejects_absolute_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("ok.txt");
        fs::write(&artifact, "ok").expect("artifact");

        let error = read_artifact(
            &state(dir.path()),
            ArtifactQuery {
                root: None,
                path: artifact.display().to_string(),
            },
        )
        .expect_err("absolute artifact path");

        assert!(error.to_string().contains("artifact path must be relative"));
    }

    #[test]
    fn artifact_rejects_relative_path_outside_default_root() {
        let parent = tempfile::tempdir().expect("tempdir");
        let default_root = parent.path().join("default-root");
        fs::create_dir_all(&default_root).expect("default root");
        fs::write(parent.path().join("outside.txt"), "outside").expect("outside artifact");

        let error = read_artifact(
            &state(&default_root),
            ArtifactQuery {
                root: None,
                path: "../outside.txt".to_string(),
            },
        )
        .expect_err("relative artifact path outside default root");

        let message = error.to_string();
        assert!(message.contains("artifact path"));
        assert!(message.contains("outside default artifact root"));
    }

    #[test]
    fn artifact_reads_relative_path_inside_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().join("case");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(case_dir.join("report.txt"), "hello\n").expect("artifact");

        let content = read_artifact(
            &state(dir.path()),
            ArtifactQuery {
                root: None,
                path: "case/report.txt".to_string(),
            },
        )
        .expect("relative artifact");

        assert_eq!(content, "hello\n");
    }

    #[test]
    fn artifact_reads_from_relative_root_inside_default_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite_dir = dir.path().join("suite");
        fs::create_dir_all(&suite_dir).expect("suite dir");
        fs::write(suite_dir.join("summary.txt"), "suite\n").expect("artifact");

        let content = read_artifact(
            &state(dir.path()),
            ArtifactQuery {
                root: Some("suite".to_string()),
                path: "summary.txt".to_string(),
            },
        )
        .expect("relative artifact root");

        assert_eq!(content, "suite\n");
    }

    #[tokio::test]
    async fn artifact_download_sets_attachment_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("ok.txt"), "ok").expect("artifact");

        let response = artifact(
            State(state(dir.path())),
            Query(ArtifactRequestQuery {
                root: None,
                path: "ok.txt".to_string(),
                download: Some("1".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"ok.txt\"")
        );
    }

    #[test]
    fn artifact_download_filename_is_header_safe() {
        assert_eq!(
            artifact_download_filename("case/failure summary.json"),
            "failure_summary.json"
        );
        assert_eq!(
            artifact_download_filename("case/bad:name?.log"),
            "bad_name_.log"
        );
    }

    #[test]
    fn artifact_returns_tail_for_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("huge.log"),
            format!("old-prefix\n{}\ntail-sentinel\n", "x".repeat(128)),
        )
        .expect("oversized artifact");

        let content = read_artifact_with_limits(
            &state(dir.path()),
            ArtifactQuery {
                root: None,
                path: "huge.log".to_string(),
            },
            ArtifactReadLimits {
                max_file_bytes: 32,
                max_directory_entries: 100,
            },
        )
        .expect("oversized artifact tail");

        assert!(content.contains("artifact truncated"));
        assert!(content.contains("tail-sentinel"));
        assert!(!content.contains("old-prefix"));
    }

    #[test]
    fn artifact_rejects_directory_over_entry_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let listing = dir.path().join("listing");
        fs::create_dir_all(&listing).expect("listing dir");
        fs::write(listing.join("a.txt"), "a").expect("a");
        fs::write(listing.join("b.txt"), "b").expect("b");
        fs::write(listing.join("c.txt"), "c").expect("c");

        let error = read_artifact_with_limits(
            &state(dir.path()),
            ArtifactQuery {
                root: None,
                path: "listing".to_string(),
            },
            ArtifactReadLimits {
                max_file_bytes: 1024,
                max_directory_entries: 2,
            },
        )
        .expect_err("large directory");

        let message = error.to_string();
        assert!(message.contains("exceeds 2 entry limit"));
        assert!(message.contains("refine the artifact path"));
    }
}
