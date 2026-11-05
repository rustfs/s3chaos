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

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::runs::{read_json, write_json};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<FaultTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ProtocolTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<MintTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultTarget {
    pub context: String,
    pub storage_class: String,
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Additional non-secret RUSTFS_FAULT_TEST_* settings for specialized scenarios.
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolTarget {
    pub endpoint: String,
    pub region: String,
    pub fingerprint: String,
    pub credentials: CredentialSource,
    /// Environment variable references for the configured OIDC provider.
    #[serde(default)]
    pub oidc: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTarget {
    pub context: String,
    pub service: String,
    pub port: Option<u16>,
    pub endpoint: Option<String>,
    pub region: String,
    pub container: String,
    pub credentials: CredentialSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSource {
    pub access_key_env: String,
    pub secret_key_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token_env: Option<String>,
}

impl Default for CredentialSource {
    fn default() -> Self {
        Self {
            access_key_env: "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY".into(),
            secret_key_env: "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY".into(),
            session_token_env: None,
        }
    }
}

impl CredentialSource {
    pub fn environment(&self) -> Result<BTreeMap<String, String>> {
        self.environment_with(|name| env::var(name).ok())
    }

    fn environment_with(
        &self,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<BTreeMap<String, String>> {
        let mut values = BTreeMap::new();
        let mut missing = Vec::new();
        for (destination, source) in [
            (
                "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY",
                Some(self.access_key_env.as_str()),
            ),
            (
                "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY",
                Some(self.secret_key_env.as_str()),
            ),
            (
                "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN",
                self.session_token_env.as_deref(),
            ),
        ] {
            let Some(source) = source else { continue };
            validate_env_name(source)?;
            if let Some(value) = get(source).filter(|value| !value.is_empty()) {
                values.insert(destination.into(), value);
            } else {
                missing.push(source);
            }
        }
        ensure!(
            missing.is_empty(),
            "missing credential environment variables: {}",
            missing.join(", ")
        );
        Ok(values)
    }
}

impl FaultTarget {
    pub fn environment(&self) -> Result<BTreeMap<String, String>> {
        let mut missing = Vec::new();
        for (name, value) in [
            ("context", &self.context),
            ("storageClass", &self.storage_class),
            ("image", &self.image),
        ] {
            if value.trim().is_empty() {
                missing.push(name);
            }
        }
        ensure!(
            missing.is_empty(),
            "missing fault target fields: {}",
            missing.join(", ")
        );
        let mut values = BTreeMap::from([
            ("S3CHAOS_TARGET_CONTEXT".into(), self.context.clone()),
            (
                "RUSTFS_FAULT_TEST_EXPECTED_CONTEXT".into(),
                self.context.clone(),
            ),
            (
                "RUSTFS_FAULT_TEST_STORAGE_CLASS".into(),
                self.storage_class.clone(),
            ),
            ("RUSTFS_FAULT_TEST_SERVER_IMAGE".into(), self.image.clone()),
        ]);
        for (key, value) in &self.options {
            validate_fault_option(key)?;
            values.insert(key.clone(), value.clone());
        }
        if let Some(namespace) = &self.namespace {
            values.insert("RUSTFS_FAULT_TEST_NAMESPACE".into(), namespace.clone());
        }
        if let Some(tenant) = &self.tenant {
            values.insert("RUSTFS_FAULT_TEST_TENANT".into(), tenant.clone());
        }
        Ok(values)
    }
}

impl ProtocolTarget {
    pub fn environment(&self) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        let mut values = self.credentials.environment()?;
        values.insert(
            "RUSTFS_PROTOCOL_TEST_ENDPOINT".into(),
            self.endpoint.clone(),
        );
        values.insert(
            "RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT".into(),
            self.fingerprint.clone(),
        );
        values.insert("RUSTFS_PROTOCOL_TEST_DEDICATED".into(), "1".into());
        for (destination, source) in &self.oidc {
            validate_env_name(destination)?;
            ensure!(
                destination.starts_with("RUSTFS_PROTOCOL_OIDC_"),
                "invalid OIDC destination {destination}"
            );
            validate_env_name(source)?;
            values.insert(
                destination.clone(),
                env::var(source)
                    .with_context(|| format!("missing OIDC environment variable {source}"))?,
            );
        }
        Ok(values)
    }

    pub fn validate(&self) -> Result<()> {
        crate::protocol::suite::resolve_protocol_endpoint(&self.endpoint)?;
        ensure!(!self.region.trim().is_empty(), "target region is required");
        ensure!(
            self.fingerprint.len() == 64
                && self
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "target fingerprint must be a verified 64-character SHA-256; run init to confirm the target"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub targets: BTreeMap<String, Target>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            targets: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = read_json(path).with_context(|| {
            format!(
                "read target configuration {}; use s3chaos init --help",
                path.display()
            )
        })?;
        ensure!(
            config.schema_version == 1,
            "unsupported target configuration version {}",
            config.schema_version
        );
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_json(path, self)
    }

    pub fn target(&self, name: &str) -> Result<Target> {
        validate_name(name)?;
        self.targets.get(name).cloned().with_context(|| {
            format!("target {name:?} is not configured; run s3chaos init --target {name}")
        })
    }
}

pub fn config_path() -> Result<PathBuf> {
    Ok(user_directory("XDG_CONFIG_HOME", ".config")?.join("s3chaos/targets.json"))
}

pub fn data_directory() -> Result<PathBuf> {
    Ok(user_directory("XDG_STATE_HOME", ".local/state")?.join("s3chaos"))
}

fn user_directory(variable: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(path) = env::var_os(variable).filter(|path| !path.is_empty()) {
        return Ok(path.into());
    }
    Ok(PathBuf::from(
        env::var_os("HOME").context("HOME is unavailable; pass --config and --data-dir")?,
    )
    .join(fallback))
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "name must contain 1..=128 ASCII letters, digits, '-' or '_'"
    );
    Ok(())
}

fn validate_env_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && !name.as_bytes()[0].is_ascii_digit(),
        "invalid environment variable name {name:?}"
    );
    Ok(())
}

fn validate_fault_option(name: &str) -> Result<()> {
    validate_env_name(name)?;
    ensure!(
        name.starts_with("RUSTFS_FAULT_TEST_"),
        "fault option must start with RUSTFS_FAULT_TEST_: {name}"
    );
    let suffix = name.trim_start_matches("RUSTFS_FAULT_TEST_");
    let reserved = [
        "EXPECTED_CONTEXT",
        "NAMESPACE",
        "TENANT",
        "SERVER_IMAGE",
        "STORAGE_CLASS",
        "ARTIFACTS_DIR",
        "ARTIFACTS",
        "RUN_ROOT",
        "DESTRUCTIVE",
        "CLEANUP",
    ];
    ensure!(
        !reserved.contains(&suffix)
            && ![
                "MUTATION_STATE",
                "SECRET",
                "PASSWORD",
                "TOKEN",
                "ACCESS_KEY",
                "SERVER_ENV"
            ]
            .iter()
            .any(|part| suffix.contains(part)),
        "{name} must be configured through its target field or runtime credential reference"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_resolved_as_one_explicit_source() {
        let source = CredentialSource {
            access_key_env: "LAB_KEY".into(),
            secret_key_env: "LAB_SECRET".into(),
            session_token_env: None,
        };
        let values = source
            .environment_with(|name| match name {
                "LAB_KEY" => Some("key-a".into()),
                "LAB_SECRET" => Some("secret-a".into()),
                "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN" => Some("unrelated-token".into()),
                _ => None,
            })
            .unwrap();
        assert_eq!(values["RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY"], "key-a");
        assert!(!values.contains_key("RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN"));
        let error = source.environment_with(|_| None).unwrap_err().to_string();
        assert!(error.contains("LAB_KEY") && error.contains("LAB_SECRET"));
    }

    #[test]
    fn options_cannot_redirect_targets_or_contain_credentials() {
        assert!(validate_fault_option("RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS").is_ok());
        for name in [
            "RUSTFS_FAULT_TEST_EXPECTED_CONTEXT",
            "RUSTFS_FAULT_TEST_RUN_ROOT",
            "RUSTFS_FAULT_TEST_SERVER_ENV",
            "PATH",
        ] {
            assert!(validate_fault_option(name).is_err());
        }
    }
}
