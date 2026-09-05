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

//! Shared signed RustFS admin transport plus narrow runtime facts. Product
//! workflows own mutation policy; this module only provides HTTP mechanics.

use anyhow::{Context, Result, bail, ensure};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use http::{Method, Request};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

const ADMIN_INFO_PATH: &str = "/rustfs/admin/v3/info";

#[derive(Clone)]
pub(crate) struct RustfsAdminTransport {
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    source: &'static str,
    http: reqwest::Client,
}

pub(crate) struct RustfsAdminResponse {
    pub status: u16,
    pub request_id: Option<String>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for RustfsAdminTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustfsAdminTransport")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl RustfsAdminTransport {
    pub(crate) fn new(
        endpoint: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        source: &'static str,
    ) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&endpoint)
            .with_context(|| format!("parse RustFS admin endpoint {endpoint}"))?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.path() == "/"
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "RustFS admin endpoint must be an HTTP(S) origin without credentials, query, or fragment"
        );
        ensure!(
            !region.trim().is_empty(),
            "RustFS admin region must not be empty"
        );
        ensure!(
            !access_key.is_empty() && !secret_key.is_empty(),
            "RustFS admin credentials must not be empty"
        );
        Ok(Self {
            endpoint,
            region: region.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            session_token: session_token.map(str::to_string),
            source,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build RustFS admin HTTP client")?,
        })
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<RustfsAdminResponse> {
        ensure!(
            path.starts_with('/'),
            "RustFS admin request path must be absolute"
        );
        let mut url = reqwest::Url::parse(&self.endpoint).context("parse RustFS admin endpoint")?;
        url.set_path(path);
        url.set_query(None);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let payload_sha256 = hex::encode(Sha256::digest(&body));
        let mut request = Request::builder()
            .method(method.clone())
            .uri(url.as_str())
            .header("x-amz-content-sha256", payload_sha256);
        if let Some(content_type) = content_type {
            request = request.header(http::header::CONTENT_TYPE, content_type);
        }
        let mut request = request.body(body).context("build RustFS admin request")?;
        sign_request(
            &mut request,
            &self.region,
            &self.access_key,
            &self.secret_key,
            self.session_token.as_deref(),
            self.source,
        )?;
        let (parts, body) = request.into_parts();
        let response = self
            .http
            .request(method, url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .context("send RustFS admin request")?;
        let status = response.status().as_u16();
        let request_id = ["x-amz-request-id", "x-request-id"]
            .into_iter()
            .find_map(|name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            });
        let body = response
            .bytes()
            .await
            .context("read RustFS admin response")?
            .to_vec();
        Ok(RustfsAdminResponse {
            status,
            request_id,
            body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsErasureLayout {
    pub deployment_id: String,
    pub standard_parity: usize,
    pub total_sets: Vec<usize>,
    pub drives_per_set: Vec<usize>,
    pub online_drives: usize,
    pub offline_drives: usize,
    pub unknown_drives: usize,
    pub servers: Vec<RustfsServerLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsServerLayout {
    pub endpoint: String,
    pub drives: Vec<RustfsDriveLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsDriveLayout {
    pub uuid: String,
    pub state: String,
    pub pool_index: i32,
    pub set_index: i32,
}

#[derive(Debug, Deserialize)]
struct ServerInfoEnvelope {
    info: ServerInfoPayload,
}

#[derive(Debug, Deserialize)]
struct ServerInfoPayload {
    #[serde(rename = "deploymentID")]
    deployment_id: Option<String>,
    backend: Option<ServerInfoBackend>,
    servers: Option<Vec<ServerInfoServer>>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoBackend {
    #[serde(rename = "standardSCParity")]
    standard_sc_parity: Option<usize>,
    #[serde(rename = "totalSets")]
    total_sets: Vec<usize>,
    #[serde(rename = "totalDrivesPerSet")]
    drives_per_set: Vec<usize>,
    #[serde(rename = "onlineDisks")]
    online_drives: usize,
    #[serde(rename = "offlineDisks")]
    offline_drives: usize,
    #[serde(rename = "unknownDisks", default)]
    unknown_drives: usize,
}

#[derive(Debug, Deserialize)]
struct ServerInfoServer {
    endpoint: String,
    #[serde(rename = "drives")]
    drives: Vec<ServerInfoDrive>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoDrive {
    uuid: String,
    state: String,
    pool_index: i32,
    set_index: i32,
}

pub(crate) async fn read_erasure_layout(
    endpoint: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<RustfsErasureLayout> {
    let response = RustfsAdminTransport::new(
        endpoint,
        region,
        access_key,
        secret_key,
        None,
        "s3chaos-rustfs-runtime-info",
    )?
    .request(Method::GET, ADMIN_INFO_PATH, &[], Vec::new(), None)
    .await?;
    if !(200..300).contains(&response.status) {
        bail!(
            "RustFS runtime info request failed: status={} request_id={request_id}",
            response.status,
            request_id = response.request_id.as_deref().unwrap_or("unknown")
        );
    }
    parse_erasure_layout(&response.body)
}

fn sign_request(
    request: &mut Request<Vec<u8>>,
    region: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    source: &'static str,
) -> Result<()> {
    let identity = Credentials::new(
        access_key,
        secret_key,
        session_token.map(str::to_string),
        None,
        source,
    )
    .into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("s3")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .context("build RustFS admin signing parameters")?
        .into();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str(),
                value.to_str().context("RustFS admin header is not ASCII")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let signable = SignableRequest::new(
        request.method().as_str(),
        request.uri().to_string(),
        headers.into_iter(),
        SignableBody::Bytes(request.body()),
    )
    .context("build signable RustFS admin request")?;
    let (instructions, _) = sign(signable, &params)
        .context("sign RustFS admin request")?
        .into_parts();
    instructions.apply_to_request_http1x(request);
    Ok(())
}

fn parse_erasure_layout(response: &[u8]) -> Result<RustfsErasureLayout> {
    let envelope: ServerInfoEnvelope =
        serde_json::from_slice(response).context("decode RustFS runtime info response")?;
    let deployment_id = envelope
        .info
        .deployment_id
        .filter(|value| !value.trim().is_empty())
        .context("RustFS runtime info is missing deploymentID")?;
    let backend = envelope
        .info
        .backend
        .context("RustFS runtime info is missing erasure backend data")?;
    let standard_parity = backend
        .standard_sc_parity
        .context("RustFS runtime info is missing standardSCParity")?;
    ensure!(
        !backend.total_sets.is_empty()
            && !backend.drives_per_set.is_empty()
            && backend.total_sets.len() == backend.drives_per_set.len(),
        "RustFS runtime info has inconsistent erasure layout arrays"
    );
    let servers = envelope
        .info
        .servers
        .context("RustFS runtime info is missing server drive membership")?
        .into_iter()
        .map(|server| RustfsServerLayout {
            endpoint: server.endpoint,
            drives: server
                .drives
                .into_iter()
                .map(|drive| RustfsDriveLayout {
                    uuid: drive.uuid,
                    state: drive.state,
                    pool_index: drive.pool_index,
                    set_index: drive.set_index,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    ensure!(!servers.is_empty(), "RustFS runtime info has no servers");
    Ok(RustfsErasureLayout {
        deployment_id,
        standard_parity,
        total_sets: backend.total_sets,
        drives_per_set: backend.drives_per_set,
        online_drives: backend.online_drives,
        offline_drives: backend.offline_drives,
        unknown_drives: backend.unknown_drives,
        servers,
    })
}

#[cfg(test)]
mod tests {
    use super::{RustfsAdminTransport, parse_erasure_layout};

    #[test]
    fn admin_transport_rejects_ambiguous_endpoint_and_redacts_credentials() {
        assert!(
            RustfsAdminTransport::new(
                "https://rustfs.example/base",
                "us-east-1",
                "access",
                "secret",
                None,
                "test",
            )
            .is_err()
        );
        let transport = RustfsAdminTransport::new(
            "https://rustfs.example",
            "us-east-1",
            "visible-access",
            "visible-secret",
            Some("visible-token"),
            "test",
        )
        .expect("transport");
        let debug = format!("{transport:?}");
        assert!(!debug.contains("visible-access"));
        assert!(!debug.contains("visible-secret"));
        assert!(!debug.contains("visible-token"));
    }

    #[test]
    fn parses_runtime_erasure_layout_and_drive_health() {
        let layout = parse_erasure_layout(
            br#"{
                "info": {
                    "deploymentID": "deployment-1",
                    "backend": {
                        "standardSCParity": 4,
                        "totalSets": [1],
                        "totalDrivesPerSet": [8],
                        "onlineDisks": 8,
                        "offlineDisks": 0,
                        "unknownDisks": 0
                    },
                    "servers": [
                        {"endpoint": "http://rustfs-0.rustfs:9000", "drives": [
                            {"uuid": "drive-0", "state": "ok", "pool_index": 0, "set_index": 0}
                        ]},
                        {"endpoint": "http://rustfs-1.rustfs:9000", "drives": [
                            {"uuid": "drive-1", "state": "ok", "pool_index": 0, "set_index": 0}
                        ]}
                    ]
                }
            }"#,
        )
        .expect("layout");

        assert_eq!(layout.deployment_id, "deployment-1");
        assert_eq!(layout.standard_parity, 4);
        assert_eq!(layout.total_sets, vec![1]);
        assert_eq!(layout.drives_per_set, vec![8]);
        assert_eq!(layout.online_drives, 8);
        assert_eq!(layout.offline_drives, 0);
        assert_eq!(layout.unknown_drives, 0);
        assert_eq!(layout.servers.len(), 2);
        assert_eq!(layout.servers[0].drives[0].uuid, "drive-0");
        assert!(parse_erasure_layout(br#"{"info":{"deploymentID":"deployment-1"}}"#).is_err());
    }
}
