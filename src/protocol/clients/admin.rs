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

use crate::rustfs::RustfsAdminTransport;
use anyhow::{Context, Result};
use http::Method;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::protocol::credentials::{ActorCredential, AdminCredentials};
use crate::protocol::ports::{
    ProtocolAdminCleanupPort, ProtocolAdminError, ProtocolAdminServerPort, ProtocolGroupAdminPort,
    ProtocolIdentityAdminPort, ProtocolPolicyAdminPort, ProtocolServerInfo,
    ProtocolSessionAdminPort,
};

const ADMIN_PREFIX: &str = "/rustfs/admin/v3";
type AdminResult<T> = std::result::Result<T, ProtocolAdminError>;

#[derive(Debug, Clone)]
pub struct RustfsAdminClient {
    endpoint: String,
    transport: RustfsAdminTransport,
}

#[derive(Debug, Deserialize)]
struct ServerInfoEnvelope {
    info: ServerInfoPayload,
}

#[derive(Debug, Deserialize)]
struct ServerInfoPayload {
    #[serde(rename = "deploymentID")]
    deployment_id: Option<String>,
    mode: Option<String>,
    region: Option<String>,
}

impl RustfsAdminClient {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        credentials: AdminCredentials,
    ) -> Result<Self> {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        let region = region.into();
        reqwest::Url::parse(&endpoint)
            .with_context(|| format!("parse RustFS admin endpoint {endpoint}"))?;
        let transport = RustfsAdminTransport::new(
            &endpoint,
            &region,
            credentials.access_key(),
            credentials.secret_key(),
            credentials.session_token(),
            "s3chaos-protocol-admin-env",
        )?;
        Ok(Self {
            endpoint,
            transport,
        })
    }

    pub async fn server_info(&self) -> AdminResult<ProtocolServerInfo> {
        let response = self
            .request(Method::GET, "/info", &[], Vec::new(), None)
            .await?;
        let envelope: ServerInfoEnvelope = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidServerInfoResponse"))?;
        let deployment_id = envelope
            .info
            .deployment_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| ProtocolAdminError::protocol("MissingDeploymentId"))?;
        Ok(ProtocolServerInfo {
            deployment_id,
            mode: envelope.info.mode,
            region: envelope.info.region,
        })
    }

    pub async fn users_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        let response = self
            .request(Method::GET, "/list-users", &[], Vec::new(), None)
            .await?;
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidListUsersResponse"))?;
        let users = value
            .as_object()
            .ok_or_else(|| ProtocolAdminError::protocol("InvalidListUsersResponse"))?
            .keys()
            .filter(|name| name.starts_with(prefix))
            .cloned()
            .collect();
        Ok(users)
    }

    pub async fn create_user(&self, credential: &ActorCredential) -> AdminResult<()> {
        let body = serde_json::to_vec(&json!({
            "secretKey": credential.secret_key(),
            "status": "enabled"
        }))
        .map_err(|_| ProtocolAdminError::protocol("EncodeCreateUserRequest"))?;
        self.request(
            Method::PUT,
            "/add-user",
            &[("accessKey", credential.access_key())],
            body,
            Some("application/json"),
        )
        .await?;
        Ok(())
    }

    pub async fn remove_user(&self, access_key: &str) -> AdminResult<()> {
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

    pub async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<()> {
        if !matches!(provider, "builtin" | "ldap" | "openid") {
            return Err(ProtocolAdminError::protocol("InvalidIdentityProvider"));
        }
        let path = format!("/revoke-tokens/{provider}");
        self.request(
            Method::POST,
            &path,
            &[("user", parent_access_key), ("fullRevoke", "true")],
            Vec::new(),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn policy_attached(
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
            .map_err(|_| ProtocolAdminError::protocol("InvalidPolicyAttachmentReadback"))?;
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

    pub async fn group_contains_member(&self, group: &str, member: &str) -> AdminResult<bool> {
        let response = match self
            .request(Method::GET, "/group", &[("group", group)], Vec::new(), None)
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_not_found() => return Ok(false),
            Err(error) => return Err(error),
        };
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidGroupMembershipReadback"))?;
        Ok(value
            .get("members")
            .and_then(Value::as_array)
            .is_some_and(|members| members.iter().any(|item| item.as_str() == Some(member))))
    }

    pub async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<Vec<String>> {
        let path = match provider {
            "builtin" => "/list-access-keys-bulk",
            "ldap" => "/idp/ldap/list-access-keys-bulk",
            "openid" => "/idp/openid/list-access-keys-bulk",
            _ => return Err(ProtocolAdminError::protocol("InvalidIdentityProvider")),
        };
        let response = self
            .request(
                Method::GET,
                path,
                &[("users", parent_access_key), ("listType", "sts-only")],
                Vec::new(),
                None,
            )
            .await?;
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidListStsSessionsResponse"))?;
        let sessions = value
            .get(parent_access_key)
            .and_then(|entry| entry.get("stsKeys"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("accessKey").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        Ok(sessions)
    }

    pub async fn policies_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        let response = self
            .request(Method::GET, "/list-canned-policies", &[], Vec::new(), None)
            .await?;
        let policies: Value = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidListPoliciesResponse"))?;
        let policies = policies
            .as_object()
            .ok_or_else(|| ProtocolAdminError::protocol("InvalidListPoliciesResponse"))?
            .keys()
            .filter(|name| name.starts_with(prefix))
            .cloned()
            .collect();
        Ok(policies)
    }

    pub async fn groups_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        let response = self
            .request(Method::GET, "/groups", &[], Vec::new(), None)
            .await?;
        let groups: Vec<String> = serde_json::from_slice(&response)
            .map_err(|_| ProtocolAdminError::protocol("InvalidListGroupsResponse"))?;
        Ok(groups
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .collect())
    }

    pub async fn create_policy(&self, name: &str, document: &str) -> AdminResult<()> {
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

    pub async fn remove_policy(&self, name: &str) -> AdminResult<()> {
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

    pub async fn attach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        self.change_policy_attachment("/idp/builtin/policy/attach", policy, principal, is_group)
            .await
    }

    pub async fn detach_policy(
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

    pub async fn update_group_members(
        &self,
        group: &str,
        members: &[String],
        remove: bool,
    ) -> AdminResult<()> {
        let body = serde_json::to_vec(&json!({
            "group": group,
            "members": members,
            "isRemove": remove,
            "groupStatus": "enabled",
        }))
        .map_err(|_| ProtocolAdminError::protocol("EncodeGroupMembershipRequest"))?;
        self.request(
            Method::PUT,
            "/update-group-members",
            &[],
            body,
            Some("application/json"),
        )
        .await?;
        Ok(())
    }

    pub async fn remove_group(&self, group: &str) -> AdminResult<()> {
        let mut url =
            reqwest::Url::parse(&format!("{}{}{}", self.endpoint, ADMIN_PREFIX, "/group/"))
                .map_err(|_| ProtocolAdminError::protocol("InvalidGroupDeleteUrl"))?;
        url.path_segments_mut()
            .map_err(|_| ProtocolAdminError::protocol("InvalidGroupDeleteUrl"))?
            .pop_if_empty()
            .push(group);
        let path = url
            .path()
            .strip_prefix(ADMIN_PREFIX)
            .ok_or_else(|| ProtocolAdminError::protocol("InvalidGroupDeleteUrl"))?
            .to_string();
        match self
            .request(Method::DELETE, &path, &[], Vec::new(), None)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> AdminResult<Vec<u8>> {
        if !path.starts_with('/') {
            return Err(ProtocolAdminError::protocol("InvalidAdminRequestPath"));
        }
        let response = self
            .transport
            .request(
                method,
                &format!("{ADMIN_PREFIX}{path}"),
                query,
                body,
                content_type,
            )
            .await
            .map_err(|_| ProtocolAdminError::transport("AdminTransportError"))?;
        if !(200..300).contains(&response.status) {
            let code = protocol_error_code(&response.body)
                .unwrap_or_else(|| "AdminRequestFailed".to_string());
            return Err(ProtocolAdminError::service(
                code,
                response.status,
                response.request_id,
            ));
        }
        Ok(response.body)
    }
}

fn policy_attachment_body(policy: &str, principal: &str, is_group: bool) -> AdminResult<Vec<u8>> {
    let target_field = if is_group { "group" } else { "user" };
    serde_json::to_vec(&json!({
        "policies": [policy],
        (target_field): principal,
    }))
    .map_err(|_| ProtocolAdminError::protocol("EncodePolicyAttachmentRequest"))
}

#[async_trait::async_trait]
impl ProtocolAdminServerPort for RustfsAdminClient {
    async fn server_info(&self) -> AdminResult<ProtocolServerInfo> {
        RustfsAdminClient::server_info(self).await
    }
}

#[async_trait::async_trait]
impl ProtocolIdentityAdminPort for RustfsAdminClient {
    async fn users_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        RustfsAdminClient::users_with_prefix(self, prefix).await
    }

    async fn create_user(&self, credential: &ActorCredential) -> AdminResult<()> {
        RustfsAdminClient::create_user(self, credential).await
    }

    async fn remove_user(&self, access_key: &str) -> AdminResult<()> {
        RustfsAdminClient::remove_user(self, access_key).await
    }
}

#[async_trait::async_trait]
impl ProtocolSessionAdminPort for RustfsAdminClient {
    async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<()> {
        RustfsAdminClient::revoke_sts_sessions_for_provider(self, parent_access_key, provider).await
    }

    async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<Vec<String>> {
        RustfsAdminClient::sts_sessions_with_parent_for_provider(self, parent_access_key, provider)
            .await
    }
}

#[async_trait::async_trait]
impl ProtocolPolicyAdminPort for RustfsAdminClient {
    async fn policy_attached(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<bool> {
        RustfsAdminClient::policy_attached(self, policy, principal, is_group).await
    }

    async fn policies_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        RustfsAdminClient::policies_with_prefix(self, prefix).await
    }

    async fn create_policy(&self, name: &str, document: &str) -> AdminResult<()> {
        RustfsAdminClient::create_policy(self, name, document).await
    }

    async fn remove_policy(&self, name: &str) -> AdminResult<()> {
        RustfsAdminClient::remove_policy(self, name).await
    }

    async fn attach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        RustfsAdminClient::attach_policy(self, policy, principal, is_group).await
    }

    async fn detach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        RustfsAdminClient::detach_policy(self, policy, principal, is_group).await
    }
}

#[async_trait::async_trait]
impl ProtocolGroupAdminPort for RustfsAdminClient {
    async fn groups_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        RustfsAdminClient::groups_with_prefix(self, prefix).await
    }

    async fn group_contains_member(&self, group: &str, member: &str) -> AdminResult<bool> {
        RustfsAdminClient::group_contains_member(self, group, member).await
    }

    async fn update_group_members(
        &self,
        group: &str,
        members: &[String],
        remove: bool,
    ) -> AdminResult<()> {
        RustfsAdminClient::update_group_members(self, group, members, remove).await
    }

    async fn remove_group(&self, group: &str) -> AdminResult<()> {
        RustfsAdminClient::remove_group(self, group).await
    }
}

#[async_trait::async_trait]
impl ProtocolAdminCleanupPort for RustfsAdminClient {
    async fn users_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        ProtocolIdentityAdminPort::users_with_prefix(self, prefix).await
    }

    async fn remove_user(&self, access_key: &str) -> AdminResult<()> {
        ProtocolIdentityAdminPort::remove_user(self, access_key).await
    }

    async fn groups_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        ProtocolGroupAdminPort::groups_with_prefix(self, prefix).await
    }

    async fn group_contains_member(&self, group: &str, member: &str) -> AdminResult<bool> {
        ProtocolGroupAdminPort::group_contains_member(self, group, member).await
    }

    async fn update_group_members(
        &self,
        group: &str,
        members: &[String],
        remove: bool,
    ) -> AdminResult<()> {
        ProtocolGroupAdminPort::update_group_members(self, group, members, remove).await
    }

    async fn remove_group(&self, group: &str) -> AdminResult<()> {
        ProtocolGroupAdminPort::remove_group(self, group).await
    }

    async fn policies_with_prefix(&self, prefix: &str) -> AdminResult<Vec<String>> {
        ProtocolPolicyAdminPort::policies_with_prefix(self, prefix).await
    }

    async fn remove_policy(&self, name: &str) -> AdminResult<()> {
        ProtocolPolicyAdminPort::remove_policy(self, name).await
    }

    async fn detach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<()> {
        ProtocolPolicyAdminPort::detach_policy(self, policy, principal, is_group).await
    }

    async fn policy_attached(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> AdminResult<bool> {
        ProtocolPolicyAdminPort::policy_attached(self, policy, principal, is_group).await
    }

    async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<()> {
        ProtocolSessionAdminPort::revoke_sts_sessions_for_provider(
            self,
            parent_access_key,
            provider,
        )
        .await
    }

    async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> AdminResult<Vec<String>> {
        ProtocolSessionAdminPort::sts_sessions_with_parent_for_provider(
            self,
            parent_access_key,
            provider,
        )
        .await
    }
}

fn protocol_error_code(body: &[u8]) -> Option<String> {
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
    use super::{policy_attachment_body, protocol_error_code};

    #[test]
    fn extracts_only_structured_admin_error_code() {
        assert_eq!(
            protocol_error_code(b"<Error><Code>NoSuchUser</Code><Message>secret</Message></Error>"),
            Some("NoSuchUser".to_string())
        );
        assert_eq!(
            protocol_error_code(br#"{"code":"NoSuchGroup","message":"secret"}"#),
            Some("NoSuchGroup".to_string())
        );
        assert_eq!(protocol_error_code(b"plain 404 page"), None);
    }

    #[test]
    fn policy_attachment_body_uses_exactly_one_principal_kind() {
        let user: serde_json::Value = serde_json::from_slice(
            &policy_attachment_body("readonly", "alice", false).expect("user body"),
        )
        .expect("user json");
        assert_eq!(user["user"], "alice");
        assert!(user.get("group").is_none());

        let group: serde_json::Value = serde_json::from_slice(
            &policy_attachment_body("readonly", "ops", true).expect("group body"),
        )
        .expect("group json");
        assert_eq!(group["group"], "ops");
        assert!(group.get("user").is_none());
    }
}
