// Copyright 2026 RustFS Team
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

//! IAM wire operations shared by the protocol and fault adapters.

use super::{RustfsAdminResponse, RustfsAdminTransport};
use http::Method;
use serde_json::{Value, json};

pub(crate) const ADMIN_PREFIX: &str = "/rustfs/admin/v3";
type AdminResult<T> = std::result::Result<T, RustfsAdminError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustfsAdminError {
    pub code: String,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    pub transient: bool,
}

impl RustfsAdminError {
    fn protocol(code: &str) -> Self {
        Self {
            code: code.to_string(),
            status: None,
            request_id: None,
            transient: false,
        }
    }

    fn is_not_found(&self) -> bool {
        matches!(
            self.code.as_str(),
            "NoSuchUser" | "NoSuchGroup" | "NoSuchPolicy" | "NoSuchEntity"
        )
    }
}

impl std::fmt::Display for RustfsAdminError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "admin request failed: code={} status={} request_id={}",
            self.code,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.request_id.as_deref().unwrap_or("unknown")
        )
    }
}
impl std::error::Error for RustfsAdminError {}

pub(crate) async fn checked_admin_request(
    transport: &RustfsAdminTransport,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    body: Vec<u8>,
    content_type: Option<&str>,
) -> AdminResult<RustfsAdminResponse> {
    if !path.starts_with('/') {
        return Err(RustfsAdminError::protocol("InvalidAdminRequestPath"));
    }
    let response = transport
        .request(
            method,
            &format!("{ADMIN_PREFIX}{path}"),
            query,
            body,
            content_type,
        )
        .await
        .map_err(|_| RustfsAdminError {
            code: "AdminTransportError".to_string(),
            status: None,
            request_id: None,
            transient: true,
        })?;
    if !(200..300).contains(&response.status) {
        return Err(RustfsAdminError {
            code: admin_error_code(&response.body)
                .unwrap_or_else(|| "AdminRequestFailed".to_string()),
            status: Some(response.status),
            request_id: response.request_id,
            transient: response.status == 408 || response.status == 429 || response.status >= 500,
        });
    }
    Ok(response)
}

#[derive(Debug, Clone)]
pub(crate) struct RustfsIdentityAdminClient {
    transport: RustfsAdminTransport,
}

pub(crate) struct RustfsIdentityInventory {
    pub names: Vec<String>,
    pub response: RustfsAdminResponse,
}

impl RustfsIdentityAdminClient {
    pub(crate) fn from_transport(transport: RustfsAdminTransport) -> Self {
        Self { transport }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> AdminResult<Vec<u8>> {
        Ok(
            checked_admin_request(&self.transport, method, path, query, body, content_type)
                .await?
                .body,
        )
    }

    pub(crate) async fn users_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        Ok(self
            .users_inventory()
            .await?
            .names
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .collect())
    }

    pub(crate) async fn users_inventory(&self) -> AdminResult<RustfsIdentityInventory> {
        self.inventory("/list-users", "InvalidListUsersResponse")
            .await
    }

    async fn inventory(
        &self,
        path: &str,
        invalid_response: &str,
    ) -> AdminResult<RustfsIdentityInventory> {
        let response =
            checked_admin_request(&self.transport, Method::GET, path, &[], Vec::new(), None)
                .await?;
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|_| RustfsAdminError::protocol(invalid_response))?;
        let names = value
            .as_object()
            .ok_or_else(|| RustfsAdminError::protocol(invalid_response))?
            .keys()
            .cloned()
            .collect();
        Ok(RustfsIdentityInventory { names, response })
    }

    pub(crate) async fn create_user(&self, access_key: &str, secret_key: &str) -> AdminResult<()> {
        let body = serde_json::to_vec(&json!({ "secretKey": secret_key, "status": "enabled" }))
            .map_err(|_| RustfsAdminError::protocol("EncodeCreateUserRequest"))?;
        self.request(
            Method::PUT,
            "/add-user",
            &[("accessKey", access_key)],
            body,
            Some("application/json"),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn set_user_secret_key(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> AdminResult<()> {
        let body = serde_json::to_vec(&json!({ "secret_key": secret_key }))
            .map_err(|_| RustfsAdminError::protocol("EncodeSecretRotationRequest"))?;
        self.request(
            Method::PUT,
            "/set-user-secret-key",
            &[("accessKey", access_key)],
            body,
            Some("application/json"),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn remove_user(&self, access_key: &str) -> AdminResult<()> {
        match self
            .request(
                Method::DELETE,
                "/remove-user",
                &[("accessKey", access_key)],
                Vec::new(),
                None,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn policies_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        Ok(self
            .policies_inventory()
            .await?
            .names
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .collect())
    }

    pub(crate) async fn policies_inventory(&self) -> AdminResult<RustfsIdentityInventory> {
        self.inventory("/list-canned-policies", "InvalidListPoliciesResponse")
            .await
    }

    pub(crate) async fn create_policy(&self, name: &str, document: &str) -> AdminResult<()> {
        self.request(
            Method::PUT,
            "/add-canned-policy",
            &[("name", name)],
            document.as_bytes().to_vec(),
            Some("application/json"),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn remove_policy(&self, name: &str) -> AdminResult<()> {
        match self
            .request(
                Method::DELETE,
                "/remove-canned-policy",
                &[("name", name)],
                Vec::new(),
                None,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn attach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        self.change_policy_attachment("/idp/builtin/policy/attach", policy, principal, is_group)
            .await
    }

    pub(crate) async fn detach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        self.change_policy_attachment("/idp/builtin/policy/detach", policy, principal, is_group)
            .await
    }

    async fn change_policy_attachment(
        &self,
        path: &str,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        let body = policy_attachment_body(policy, principal, is_group)?;
        self.request(Method::POST, path, &[], body, Some("application/json"))
            .await?;
        Ok(())
    }

    pub(crate) async fn policy_attached(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<bool> {
        let (path, query) = if is_group {
            ("/group", vec![("group", principal)])
        } else {
            ("/list-users", Vec::new())
        };
        let response = match self
            .request(Method::GET, path, &query, Vec::new(), None)
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_not_found() => return Ok(false),
            Err(error) => return Err(error),
        };
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| RustfsAdminError::protocol("InvalidPolicyAttachmentReadback"))?;
        let policy_names = if is_group {
            value.get("policy").and_then(Value::as_str)
        } else {
            value
                .get(principal)
                .and_then(|user| user.get("policyName"))
                .and_then(Value::as_str)
        };
        Ok(policy_names
            .is_some_and(|names| names.split(',').map(str::trim).any(|name| name == policy)))
    }
}

pub(crate) fn policy_attachment_body(
    policy: &str,
    principal: &str,
    is_group: bool,
) -> AdminResult<Vec<u8>> {
    let target = if is_group { "group" } else { "user" };
    serde_json::to_vec(&json!({ "policies": [policy], (target): principal }))
        .map_err(|_| RustfsAdminError::protocol("EncodePolicyAttachmentRequest"))
}

pub(crate) fn admin_error_code(body: &[u8]) -> Option<String> {
    if let Ok(value) = serde_json::from_slice::<Value>(body)
        && let Some(code) = value
            .get("Code")
            .or_else(|| value.get("code"))
            .and_then(Value::as_str)
    {
        return Some(code.to_string());
    }
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let end = text[start..].find("</Code>")? + start;
    Some(text[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::to_bytes, http::StatusCode, routing::any};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn native_secret_rotation_uses_dedicated_signed_wire_api() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let requests = captured.clone();
        let app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let requests = requests.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 4096).await.expect("body");
                requests.lock().expect("requests").push((
                    parts.method,
                    parts.uri,
                    parts.headers,
                    serde_json::from_slice::<Value>(&bytes).expect("json"),
                ));
                (StatusCode::OK, "{}")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "wire-test",
        )
        .expect("transport");
        let client = RustfsIdentityAdminClient::from_transport(transport);
        client
            .create_user("owned-user", "old-secret")
            .await
            .expect("create");
        client
            .set_user_secret_key("owned-user", "new-secret")
            .await
            .expect("rotation");
        let requests = captured.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].1.path(), "/rustfs/admin/v3/add-user");
        assert_eq!(
            requests[0].3,
            json!({ "secretKey": "old-secret", "status": "enabled" })
        );
        let rotation = &requests[1];
        assert_eq!(rotation.0, Method::PUT);
        assert_eq!(rotation.1.path(), "/rustfs/admin/v3/set-user-secret-key");
        assert_eq!(rotation.1.query(), Some("accessKey=owned-user"));
        assert_eq!(rotation.3, json!({ "secret_key": "new-secret" }));
        assert!(
            rotation
                .2
                .get("authorization")
                .expect("signature")
                .to_str()
                .expect("text")
                .starts_with("AWS4-HMAC-SHA256 Credential=admin-access/")
        );
        server.abort();
    }

    #[tokio::test]
    async fn admin_failures_preserve_status_and_drop_response_messages() {
        let app = Router::new().fallback(any(|| async {
            (
                StatusCode::FORBIDDEN,
                "<Error><Code>AccessDenied</Code><Message>private-secret</Message></Error>",
            )
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "wire-test",
        )
        .expect("transport");
        let client = RustfsIdentityAdminClient::from_transport(transport);
        let error = client
            .set_user_secret_key("owned-user", "new-secret")
            .await
            .expect_err("denied");
        assert_eq!(error.code, "AccessDenied");
        assert_eq!(error.status, Some(403));
        assert!(!error.transient);
        assert!(!format!("{error:#}").contains("private-secret"));
        assert!(!format!("{client:?}").contains("admin-secret"));
        server.abort();
    }

    #[tokio::test]
    async fn identity_inventory_keeps_response_receipts_and_exact_local_names() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let observed = paths.clone();
        let app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let observed = observed.clone();
            async move {
                assert_eq!(request.method(), Method::GET);
                assert!(request.headers().contains_key("authorization"));
                let path = request.uri().path().to_string();
                observed.lock().expect("paths").push(path.clone());
                let body = if path.ends_with("list-users") {
                    r#"{"owned-user":{"status":"enabled"},"owned-user-other":{"status":"disabled"}}"#
                } else {
                    r#"{"owned-policy":{"Version":"2012-10-17"}}"#
                };
                (StatusCode::OK, [("x-amz-request-id", "local-pod-request")], body)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "inventory-test",
        )
        .expect("transport");
        let client = RustfsIdentityAdminClient::from_transport(transport);
        let users = client.users_inventory().await.expect("users");
        assert_eq!(users.names, ["owned-user", "owned-user-other"]);
        assert_eq!(users.response.status, 200);
        assert_eq!(
            users.response.request_id.as_deref(),
            Some("local-pod-request")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&users.response.body).expect("body")["owned-user"]["status"],
            "enabled"
        );
        let policies = client.policies_inventory().await.expect("policies");
        assert_eq!(policies.names, ["owned-policy"]);
        assert_eq!(
            *paths.lock().expect("paths"),
            [
                "/rustfs/admin/v3/list-users",
                "/rustfs/admin/v3/list-canned-policies"
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn malformed_successful_inventory_response_does_not_prove_absence() {
        let app = Router::new().fallback(any(|| async { (StatusCode::OK, "[]") }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "inventory-test",
        )
        .expect("transport");
        let client = RustfsIdentityAdminClient::from_transport(transport);
        let error = client
            .users_inventory()
            .await
            .err()
            .expect("malformed response");
        assert_eq!(error.code, "InvalidListUsersResponse");
        assert!(client.policies_inventory().await.is_err());
        server.abort();
    }
}
