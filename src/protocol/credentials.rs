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

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

const ADMIN_ACCESS_KEY_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY";
const ADMIN_SECRET_KEY_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY";
const ADMIN_SESSION_TOKEN_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN";

pub use crate::rustfs::SecretString;

#[derive(Clone)]
pub struct ExternalIdentityCredential {
    pub username: String,
    pub source_resource_id: String,
    password: SecretString,
}

impl ExternalIdentityCredential {
    pub fn generated(
        username: impl Into<String>,
        source_resource_id: impl Into<String>,
    ) -> Result<Self> {
        let nonce = format!("{}:{}", Uuid::new_v4(), Uuid::new_v4());
        Ok(Self {
            username: username.into(),
            source_resource_id: source_resource_id.into(),
            password: SecretString::new(hex::encode(Sha256::digest(nonce.as_bytes())))?,
        })
    }

    pub(crate) fn password(&self) -> &str {
        self.password.expose()
    }
}

impl fmt::Debug for ExternalIdentityCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalIdentityCredential")
            .field("username", &self.username)
            .field("source_resource_id", &self.source_resource_id)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct WebIdentityToken(SecretString);

impl WebIdentityToken {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(SecretString::new(value)?))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for WebIdentityToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct AdminCredentials {
    pub(crate) access_key: SecretString,
    pub(crate) secret_key: SecretString,
    pub(crate) session_token: Option<SecretString>,
}

impl AdminCredentials {
    pub(crate) fn access_key(&self) -> &str {
        self.access_key.expose()
    }

    pub(crate) fn secret_key(&self) -> &str {
        self.secret_key.expose()
    }

    pub(crate) fn session_token(&self) -> Option<&str> {
        self.session_token.as_ref().map(SecretString::expose)
    }
}

impl fmt::Debug for AdminCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminCredentials")
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub trait CredentialProvider {
    fn resolve(&self, profile: &str) -> Result<AdminCredentials>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EnvCredentialProvider;

impl CredentialProvider for EnvCredentialProvider {
    fn resolve(&self, profile: &str) -> Result<AdminCredentials> {
        ensure!(
            !profile.trim().is_empty(),
            "admin profile must not be empty"
        );
        let access_key = std::env::var(ADMIN_ACCESS_KEY_ENV)
            .with_context(|| format!("{ADMIN_ACCESS_KEY_ENV} is required"))?;
        let secret_key = std::env::var(ADMIN_SECRET_KEY_ENV)
            .with_context(|| format!("{ADMIN_SECRET_KEY_ENV} is required"))?;
        let session_token = std::env::var(ADMIN_SESSION_TOKEN_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .map(SecretString::new)
            .transpose()?;

        Ok(AdminCredentials {
            access_key: SecretString::new(access_key)?,
            secret_key: SecretString::new(secret_key)?,
            session_token,
        })
    }
}

#[derive(Clone)]
pub struct ActorCredential {
    pub actor_id: String,
    pub credential_id: String,
    pub source_resource_id: String,
    pub creation_phase: String,
    pub expiration: Option<String>,
    access_key: SecretString,
    secret_key: SecretString,
    session_token: Option<SecretString>,
}

impl fmt::Debug for ActorCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActorCredential")
            .field("actor_id", &self.actor_id)
            .field("credential_id", &self.credential_id)
            .field("source_resource_id", &self.source_resource_id)
            .field("creation_phase", &self.creation_phase)
            .field("expiration", &self.expiration)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl ActorCredential {
    pub fn generated(
        actor_id: impl Into<String>,
        access_key: impl Into<String>,
        source_resource_id: impl Into<String>,
    ) -> Result<Self> {
        let access_key = access_key.into();
        let nonce = format!("{}:{}", Uuid::new_v4(), Uuid::new_v4());
        let secret_key = hex::encode(Sha256::digest(nonce.as_bytes()));
        Ok(Self {
            actor_id: actor_id.into(),
            credential_id: format!("credential-{}", Uuid::new_v4()),
            source_resource_id: source_resource_id.into(),
            creation_phase: "case-setup".to_string(),
            expiration: None,
            access_key: SecretString::new(access_key)?,
            secret_key: SecretString::new(secret_key)?,
            session_token: None,
        })
    }

    pub(crate) fn temporary(
        actor_id: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: impl Into<String>,
        source_resource_id: impl Into<String>,
        expiration: impl Into<String>,
    ) -> Result<Self> {
        Self::temporary_for_phase(
            actor_id,
            access_key,
            secret_key,
            session_token,
            source_resource_id,
            expiration,
            "sts-assume-role",
        )
    }

    pub(crate) fn temporary_for_phase(
        actor_id: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: impl Into<String>,
        source_resource_id: impl Into<String>,
        expiration: impl Into<String>,
        creation_phase: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            actor_id: actor_id.into(),
            credential_id: format!("credential-{}", Uuid::new_v4()),
            source_resource_id: source_resource_id.into(),
            creation_phase: creation_phase.into(),
            expiration: Some(expiration.into()),
            access_key: SecretString::new(access_key)?,
            secret_key: SecretString::new(secret_key)?,
            session_token: Some(SecretString::new(session_token)?),
        })
    }

    pub(crate) fn access_key(&self) -> &str {
        self.access_key.expose()
    }

    pub(crate) fn secret_key(&self) -> &str {
        self.secret_key.expose()
    }

    pub(crate) fn session_token(&self) -> Option<&str> {
        self.session_token.as_ref().map(SecretString::expose)
    }

    pub fn artifact(&self) -> ActorCredentialArtifact {
        ActorCredentialArtifact {
            actor_id: self.actor_id.clone(),
            credential_id: self.credential_id.clone(),
            source_resource_id: self.source_resource_id.clone(),
            creation_phase: self.creation_phase.clone(),
            expiration: self.expiration.clone(),
            redacted: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActorCredentialArtifact {
    pub actor_id: String,
    pub credential_id: String,
    pub source_resource_id: String,
    pub creation_phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    pub redacted: bool,
}

#[cfg(test)]
mod tests {
    use super::{ActorCredential, ExternalIdentityCredential, WebIdentityToken};

    #[test]
    fn actor_credential_debug_and_artifact_hide_secrets() {
        let credential = ActorCredential::generated("actor", "generated-user", "resource-1")
            .expect("credential");
        let debug = format!("{credential:?}");
        let artifact = serde_json::to_string(&credential.artifact()).expect("artifact");

        assert!(!debug.contains(credential.access_key()));
        assert!(!debug.contains(credential.secret_key()));
        assert!(!artifact.contains(credential.access_key()));
        assert!(!artifact.contains(credential.secret_key()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn temporary_credential_artifact_hides_session_material() {
        let credential = ActorCredential::temporary(
            "session",
            "temporary-access",
            "temporary-secret",
            "temporary-token",
            "resource-1",
            "2099-01-01T00:00:00Z",
        )
        .expect("credential");
        let debug = format!("{credential:?}");
        let artifact = serde_json::to_string(&credential.artifact()).expect("artifact");
        for secret in ["temporary-access", "temporary-secret", "temporary-token"] {
            assert!(!debug.contains(secret));
            assert!(!artifact.contains(secret));
        }
        assert!(artifact.contains("2099-01-01T00:00:00Z"));
    }

    #[test]
    fn external_identity_material_is_redacted() {
        let identity = ExternalIdentityCredential::generated("oidc-user", "resource-1")
            .expect("external identity");
        let token = WebIdentityToken::new("header.payload.signature").expect("token");

        assert!(!format!("{identity:?}").contains(identity.password()));
        assert!(!format!("{token:?}").contains(token.expose()));
    }
}
