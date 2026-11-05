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
use async_trait::async_trait;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::protocol::{
    clients::{
        admin::RustfsAdminClient,
        keycloak::{KeycloakEnvironment, KeycloakExternalIdentityProvider},
        s3::ProtocolS3Client,
        sts::RustfsStsClient,
        web_identity::RustfsWebIdentityStsClient,
    },
    credentials::{AdminCredentials, CredentialProvider, EnvCredentialProvider},
    runner::executor::{ProtocolClock, ProtocolShutdownSignal, ProtocolTimeoutPolicy},
    suite::{
        ProtocolExecutionTimeouts, ProtocolSuite, ResolvedProtocolSuite, resolve_protocol_endpoint,
        resolve_protocol_suite_yaml, validate_protocol_ci_environment,
    },
};

const DEFAULT_ARTIFACT_BASE: &str = "target/protocol-tests";

/// Connected outer-layer adapters for one protocol-suite invocation.
///
/// Construction lives here so the suite executor never imports or instantiates
/// AWS, RustFS Admin, STS, or Keycloak implementations.
pub(crate) struct ConnectedProtocolRuntime {
    pub(crate) suite: ResolvedProtocolSuite,
    pub(crate) endpoint: String,
    pub(crate) credentials: AdminCredentials,
    pub(crate) admin: RustfsAdminClient,
    pub(crate) s3: ProtocolS3Client,
    pub(crate) sts: RustfsStsClient,
    pub(crate) external_identity: Option<KeycloakExternalIdentityProvider>,
    pub(crate) external_identity_configuration_error: Option<String>,
    pub(crate) web_identity_sts: Option<RustfsWebIdentityStsClient>,
}

impl ConnectedProtocolRuntime {
    pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let suite = resolve_protocol_suite_yaml(path)?;
        Self::connect_resolved(suite).await
    }

    pub(crate) async fn connect_suite(suite: &ProtocolSuite) -> Result<Self> {
        Self::connect_resolved(suite.resolve()?).await
    }

    async fn connect_resolved(suite: ResolvedProtocolSuite) -> Result<Self> {
        let endpoint = resolve_protocol_endpoint(&suite.target.endpoint)?;
        let credentials = EnvCredentialProvider.resolve(&suite.target.credentials.admin_profile)?;
        let admin = RustfsAdminClient::new(&endpoint, &suite.target.region, credentials.clone())?;
        let s3 = ProtocolS3Client::for_admin(&endpoint, &suite.target.region, &credentials).await?;
        let sts = RustfsStsClient::new(&endpoint, &suite.target.region)?;
        let (external_identity, external_identity_configuration_error, web_identity_sts) =
            match &suite.target.external_identity {
                Some(config) => {
                    let web_identity_sts = Some(RustfsWebIdentityStsClient::new(&endpoint)?);
                    match KeycloakExternalIdentityProvider::from_optional_env(&config.profile) {
                        KeycloakEnvironment::Configured(provider) => {
                            (Some(*provider), None, web_identity_sts)
                        }
                        KeycloakEnvironment::Missing => (None, None, web_identity_sts),
                        KeycloakEnvironment::Broken(error) => (None, Some(error), web_identity_sts),
                    }
                }
                None => (None, None, None),
            };
        Ok(Self {
            suite,
            endpoint,
            credentials,
            admin,
            s3,
            sts,
            external_identity,
            external_identity_configuration_error,
            web_identity_sts,
        })
    }
}

pub(crate) struct MonotonicProtocolClock {
    started: Instant,
}

impl Default for MonotonicProtocolClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ProtocolClock for MonotonicProtocolClock {
    fn now_millis(&self) -> u128 {
        self.started.elapsed().as_millis()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BudgetedProtocolTimeout {
    case_timeout: Duration,
    suite_timeout: Duration,
}

impl BudgetedProtocolTimeout {
    pub(crate) fn new(timeouts: ProtocolExecutionTimeouts) -> Self {
        Self {
            case_timeout: Duration::from_secs(timeouts.case_seconds),
            suite_timeout: Duration::from_secs(timeouts.suite_seconds),
        }
    }
}

#[async_trait]
impl ProtocolTimeoutPolicy for BudgetedProtocolTimeout {
    fn suite_budget_exhausted(&self, elapsed_millis: u128) -> bool {
        elapsed_millis >= self.suite_timeout.as_millis()
    }

    async fn wait_for_case(&self, _case_id: &str, _started_at_millis: u128) -> Result<()> {
        tokio::time::sleep(self.case_timeout).await;
        Ok(())
    }

    async fn wait_for_suite(
        &self,
        _suite_started_at_millis: u128,
        elapsed_millis: u128,
    ) -> Result<()> {
        let elapsed = Duration::from_millis(elapsed_millis.min(u64::MAX as u128) as u64);
        tokio::time::sleep(self.suite_timeout.saturating_sub(elapsed)).await;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProcessShutdownSignal;

#[async_trait]
impl ProtocolShutdownSignal for ProcessShutdownSignal {
    async fn wait(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .context("install SIGTERM handler for protocol cleanup")?;
            tokio::select! {
                result = tokio::signal::ctrl_c() => result.context("listen for Ctrl-C")?,
                _ = terminate.recv() => {}
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.context("listen for Ctrl-C")
        }
    }
}

pub(crate) fn protocol_artifact_base() -> PathBuf {
    std::env::var("RUSTFS_PROTOCOL_TEST_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ARTIFACT_BASE))
}

pub(crate) fn ensure_dedicated_target_acknowledgement() -> Result<()> {
    validate_protocol_ci_environment()?;
    ensure!(
        std::env::var("RUSTFS_PROTOCOL_TEST_DEDICATED").as_deref() == Ok("1"),
        "protocol tests require a dedicated RustFS target; set RUSTFS_PROTOCOL_TEST_DEDICATED=1 after verifying the target"
    );
    Ok(())
}

pub(crate) fn ensure_dedicated_target_fingerprint(
    fingerprint: &crate::protocol::suite_plan::TargetFingerprint,
) -> Result<()> {
    let expected = std::env::var("RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT").context(
        "RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT is required for destructive protocol tests",
    )?;
    validate_dedicated_target_fingerprint(fingerprint, &expected)
}

fn validate_dedicated_target_fingerprint(
    fingerprint: &crate::protocol::suite_plan::TargetFingerprint,
    expected: &str,
) -> Result<()> {
    ensure!(
        !fingerprint.deployment_id.starts_with("s3-endpoint:"),
        "protocol destructive tests require a server-verified deployment fingerprint"
    );
    ensure!(
        expected == fingerprint.sha256,
        "refuse destructive protocol tests because the dedicated target fingerprint changed: expected {expected}, observed {}",
        fingerprint.sha256
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_dedicated_target_fingerprint;
    use crate::protocol::suite_plan::TargetFingerprint;

    #[test]
    fn destructive_target_gate_requires_server_identity_and_exact_pin() {
        let verified = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        validate_dedicated_target_fingerprint(&verified, &verified.sha256)
            .expect("matching fingerprint");
        assert!(validate_dedicated_target_fingerprint(&verified, "changed").is_err());

        let synthetic = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "s3-endpoint:http://127.0.0.1:9000",
            None,
            None,
        )
        .expect("synthetic fingerprint");
        assert!(validate_dedicated_target_fingerprint(&synthetic, &synthetic.sha256).is_err());
    }
}
