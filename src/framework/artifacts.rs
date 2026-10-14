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
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::framework::{command::CommandSpec, config::ClusterTestConfig, kubectl::Kubectl};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReport {
    pub dir: PathBuf,
    pub diagnosis: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotCommand {
    file_name: String,
    command: CommandSpec,
}

#[derive(Debug, Clone)]
pub struct ArtifactCollector {
    root: PathBuf,
    reference_root: PathBuf,
    redactions: Arc<Mutex<Vec<crate::rustfs::SecretString>>>,
}

impl ArtifactCollector {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            reference_root: root.clone(),
            root,
            redactions: Arc::default(),
        }
    }

    pub(crate) fn with_reference_root(
        root: impl Into<PathBuf>,
        reference_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        let root = root.into();
        let reference_root = reference_root.into();
        ensure!(
            root.starts_with(&reference_root),
            "artifact write root {} must be inside reference root {}",
            root.display(),
            reference_root.display()
        );
        Ok(Self {
            root,
            reference_root,
            redactions: Arc::default(),
        })
    }

    pub fn case_dir(&self, case_name: &str) -> PathBuf {
        self.root.join(sanitize_case_name(case_name))
    }

    pub fn write_text(&self, case_name: &str, file_name: &str, content: &str) -> Result<PathBuf> {
        let dir = self.case_dir(case_name);
        fs::create_dir_all(&dir)?;
        let path = dir.join(file_name);
        fs::write(&path, self.redact_artifact(file_name, content)?.as_bytes())?;
        Ok(path)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn redact_secrets(&self, secrets: &[&str]) -> Result<()> {
        let values = secrets
            .iter()
            .map(|value| crate::rustfs::SecretString::new(*value))
            .collect::<Result<Vec<_>>>()?;
        self.redactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(values);
        Ok(())
    }

    pub(crate) fn redact_text<'a>(&self, content: &'a str) -> Cow<'a, str> {
        let values = self
            .redactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut patterns = Vec::with_capacity(values.len() * 2);
        for value in values.iter() {
            patterns.push(value.expose().to_string());
            let encoded = serde_json::Value::String(value.expose().to_string()).to_string();
            let escaped = &encoded[1..encoded.len() - 1];
            if escaped != value.expose() {
                patterns.push(escaped.to_string());
            }
        }
        if !patterns.iter().any(|value| content.contains(value)) {
            return Cow::Borrowed(content);
        }
        let mut redacted = content.to_string();
        for value in patterns {
            redacted = redacted.replace(&value, "[REDACTED]");
        }
        Cow::Owned(redacted)
    }

    fn redact_artifact<'a>(&self, file_name: &str, content: &'a str) -> Result<Cow<'a, str>> {
        let has_redactions = !self
            .redactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        if !has_redactions || !file_name.ends_with(".json") {
            return Ok(self.redact_text(content));
        }
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(content) else {
            return Ok(self.redact_text(content));
        };
        // JSON evidence binds exact resource identities. Only diagnostic
        // values can be redacted; a credential may equal a valid target name.
        if !self.redact_json_diagnostics(&mut value, false) {
            return Ok(Cow::Borrowed(content));
        }
        Ok(Cow::Owned(serde_json::to_string_pretty(&value)?))
    }

    fn redact_json_diagnostics(&self, value: &mut serde_json::Value, diagnostic: bool) -> bool {
        match value {
            serde_json::Value::String(text) if diagnostic => {
                if let Cow::Owned(redacted) = self.redact_text(text) {
                    *text = redacted;
                    true
                } else {
                    false
                }
            }
            serde_json::Value::Array(values) => {
                let mut changed = false;
                for value in values {
                    changed |= self.redact_json_diagnostics(value, diagnostic);
                }
                changed
            }
            serde_json::Value::Object(fields) => {
                let mut changed = false;
                for (name, value) in fields {
                    let diagnostic = diagnostic
                        || matches!(
                            name.as_str(),
                            "error"
                                | "errors"
                                | "message"
                                | "failureMessage"
                                | "failure_message"
                                | "stdout"
                                | "stderr"
                                | "diagnosis"
                        );
                    changed |= self.redact_json_diagnostics(value, diagnostic);
                }
                changed
            }
            _ => false,
        }
    }

    pub(crate) fn reference_path(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.reference_root)
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "artifact {} is outside reference root {}",
                    path.display(),
                    self.reference_root.display()
                )
            })
    }

    pub(crate) fn reference_root(&self) -> &Path {
        &self.reference_root
    }

    pub fn collect_kubernetes_snapshot(
        &self,
        case_name: &str,
        config: &ClusterTestConfig,
    ) -> Result<SnapshotReport> {
        self.collect_kubernetes_snapshot_with_diagnosis(case_name, config, generic_diagnosis)
    }

    pub fn collect_kubernetes_snapshot_with_diagnosis(
        &self,
        case_name: &str,
        config: &ClusterTestConfig,
        diagnose: impl FnOnce(&str) -> String,
    ) -> Result<SnapshotReport> {
        let mut combined_output = String::new();

        for SnapshotCommand { file_name, command } in kubernetes_snapshot_commands(config) {
            let output = command.run()?;
            let content = format!(
                "$ {cmd}\nexit: {code:?}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}\n",
                cmd = command.display(),
                code = output.code,
                stdout = output.stdout,
                stderr = output.stderr
            );
            combined_output.push_str(&self.redact_text(&content));
            combined_output.push('\n');
            self.write_text(case_name, &file_name, &content)?;
        }

        let diagnosis = self.redact_text(&diagnose(&combined_output)).into_owned();
        self.write_text(case_name, "diagnosis.txt", &diagnosis)?;

        Ok(SnapshotReport {
            dir: self.case_dir(case_name),
            diagnosis,
        })
    }
}

fn kubernetes_snapshot_commands(config: &ClusterTestConfig) -> Vec<SnapshotCommand> {
    let kubectl = Kubectl::new(config);
    let operator_kubectl = Kubectl::new(config).namespaced(&config.operator_namespace);
    let test_kubectl = Kubectl::new(config).namespaced(&config.test_namespace);
    let tenant_selector = format!("rustfs.tenant={}", config.tenant_name);
    let pv_jsonpath = concat!(
        "{range .items[*]}",
        "{.metadata.name}{\"\\t\"}",
        "{.spec.local.path}{\"\\t\"}",
        "{.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]}",
        "{\"\\t\"}{.spec.claimRef.namespace}/{.spec.claimRef.name}{\"\\n\"}",
        "{end}"
    );

    vec![
        SnapshotCommand {
            file_name: "get-all.txt".to_string(),
            command: kubectl.command(["get", "all", "-A", "-o", "wide"]),
        },
        SnapshotCommand {
            file_name: "tenants.yaml".to_string(),
            command: kubectl.command(["get", "tenants", "-A", "-o", "yaml"]),
        },
        SnapshotCommand {
            file_name: "tenant-describe.txt".to_string(),
            command: test_kubectl.command(vec![
                "describe".to_string(),
                "tenant".to_string(),
                config.tenant_name.clone(),
            ]),
        },
        SnapshotCommand {
            file_name: "events.txt".to_string(),
            command: kubectl.command(["get", "events", "-A", "--sort-by=.lastTimestamp"]),
        },
        SnapshotCommand {
            file_name: "operator.log".to_string(),
            command: operator_kubectl.command(["logs", "deployment/rustfs-operator", "--tail=500"]),
        },
        SnapshotCommand {
            file_name: "console.log".to_string(),
            command: operator_kubectl.command([
                "logs",
                "deployment/rustfs-operator-console",
                "--tail=500",
            ]),
        },
        SnapshotCommand {
            file_name: "test-namespace-pods.txt".to_string(),
            command: test_kubectl.command(["get", "pods", "-o", "wide"]),
        },
        SnapshotCommand {
            file_name: "test-namespace-pvcs.txt".to_string(),
            command: test_kubectl.command(["get", "pvc", "-o", "wide"]),
        },
        SnapshotCommand {
            file_name: "pv-paths.txt".to_string(),
            command: kubectl.command(vec![
                "get".to_string(),
                "pv".to_string(),
                "-o".to_string(),
                format!("jsonpath={pv_jsonpath}"),
            ]),
        },
        SnapshotCommand {
            file_name: "rustfs-pods-describe.txt".to_string(),
            command: test_kubectl.command(vec![
                "describe".to_string(),
                "pods".to_string(),
                "-l".to_string(),
                tenant_selector.clone(),
            ]),
        },
        SnapshotCommand {
            file_name: "rustfs-pods-current.log".to_string(),
            command: test_kubectl.command(vec![
                "logs".to_string(),
                "-l".to_string(),
                tenant_selector.clone(),
                "-c".to_string(),
                "rustfs".to_string(),
                "--tail=500".to_string(),
                "--prefix".to_string(),
            ]),
        },
        SnapshotCommand {
            file_name: "rustfs-pods-previous.log".to_string(),
            command: test_kubectl.command(vec![
                "logs".to_string(),
                "-l".to_string(),
                tenant_selector,
                "-c".to_string(),
                "rustfs".to_string(),
                "--previous".to_string(),
                "--tail=500".to_string(),
                "--prefix".to_string(),
            ]),
        },
    ]
}

fn generic_diagnosis(_: &str) -> String {
    "Kubernetes snapshot collected. Inspect the generated command outputs for the first failing resource, event, or container log.".to_string()
}

fn sanitize_case_name(case_name: &str) -> String {
    case_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ArtifactCollector, generic_diagnosis, kubernetes_snapshot_commands};
    use crate::framework::config::E2eConfig;

    #[test]
    fn run_owned_redactions_survive_collector_clones_and_cover_diagnostic_logs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let failure_collector = collector.clone();
        collector
            .redact_secrets(&["generated-access-key", "generated-secret"])
            .expect("redactions");
        drop(collector);
        let path = failure_collector
            .write_text(
                "rotation",
                "rustfs-pods-current.log",
                "accessKey=generated-access-key secret=generated-secret",
            )
            .expect("artifact");
        assert_eq!(
            std::fs::read_to_string(path).expect("log"),
            "accessKey=[REDACTED] secret=[REDACTED]"
        );
        let diagnosis =
            failure_collector.redact_text("failed generated-access-key generated-secret");
        assert_eq!(diagnosis, "failed [REDACTED] [REDACTED]");
        let debug = format!("{failure_collector:?}");
        assert!(!debug.contains("generated-access-key") && !debug.contains("generated-secret"));
    }

    #[test]
    fn json_evidence_keeps_target_identities_before_and_after_secret_registration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let value = serde_json::json!({
            "tenant": "testaccess", "namespace": "testsecret",
            "context": "context-testaccess", "bucket": "bucket-testsecret",
            "pod": {"metadata": {"name": "testaccess-0", "namespace": "testsecret",
                "uid": "uid-testaccess", "labels": {"rustfs.tenant": "testaccess"}}},
            "portForwardCommand": "kubectl --context context-testaccess -n testsecret port-forward pod/testaccess-0 19000:9000",
            "responseBodySha256": "a".repeat(64)
        });
        let content = serde_json::to_string_pretty(&value).expect("JSON");
        let before = collector
            .write_text("rotation", "run-spec.json", &content)
            .expect("spec");
        collector
            .redact_secrets(&["testaccess", "testsecret"])
            .expect("redactions");
        let after = collector
            .write_text("rotation", "credential-rotation.json", &content)
            .expect("rotation evidence");
        assert_eq!(std::fs::read_to_string(before).expect("spec"), content);
        assert_eq!(std::fs::read_to_string(after).expect("evidence"), content);
    }

    #[test]
    fn json_diagnostics_redact_nested_and_escaped_secrets_without_changing_identities() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let escaped_secret = "private\"secret\\value";
        collector
            .redact_secrets(&["testaccess", "testsecret", escaped_secret])
            .expect("redactions");
        let content = serde_json::json!({
            "tenant": "testaccess", "namespace": "testsecret",
            "error": "testaccess testsecret",
            "phases": [{"error": escaped_secret}, {"error": "testsecret"}],
            "details": {"stdout": "testaccess", "stderr": "testsecret"},
            "errors": ["testaccess", "testsecret"],
            "message": escaped_secret
        })
        .to_string();
        let path = collector
            .write_text("rotation", "failure-summary.json", &content)
            .expect("failure");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("failure JSON"))
                .expect("JSON");
        assert_eq!(value["tenant"], "testaccess");
        assert_eq!(value["namespace"], "testsecret");
        assert_eq!(value["error"], "[REDACTED] [REDACTED]");
        for path in [
            "/phases/0/error",
            "/phases/1/error",
            "/details/stdout",
            "/details/stderr",
            "/errors/0",
            "/errors/1",
            "/message",
        ] {
            assert_eq!(value.pointer(path).expect("diagnostic"), "[REDACTED]");
        }
        let log = collector
            .write_text("rotation", "rustfs.log", &content)
            .expect("log");
        let log = std::fs::read_to_string(log).expect("diagnostic log");
        assert!(!log.contains("testaccess") && !log.contains("testsecret"));
        assert!(!log.contains("private") && !log.contains("secret\\\\value"));
    }

    #[test]
    fn artifact_paths_are_case_scoped_and_sanitized() {
        let collector = ArtifactCollector::new("target/artifacts");

        assert_eq!(
            collector.case_dir("console auth/session"),
            std::path::PathBuf::from("target/artifacts/console_auth_session")
        );
    }

    #[test]
    fn snapshot_collects_tenant_logs_and_pv_paths() {
        let config = E2eConfig::defaults();
        let commands = kubernetes_snapshot_commands(&config);
        let displays: Vec<_> = commands
            .iter()
            .map(|command| command.command.display())
            .collect();

        assert!(
            displays
                .iter()
                .any(|display| display.contains("describe tenant e2e-tenant"))
        );
        assert!(
            displays
                .iter()
                .any(|display| display.contains("get pv -o jsonpath="))
        );
        assert!(displays.iter().any(|display| {
            display.contains("logs -l rustfs.tenant=e2e-tenant -c rustfs --tail=500 --prefix")
        }));
        assert!(displays.iter().any(|display| {
            display.contains(
                "logs -l rustfs.tenant=e2e-tenant -c rustfs --previous --tail=500 --prefix",
            )
        }));
    }

    #[test]
    fn default_diagnosis_stays_domain_neutral() {
        let diagnosis = generic_diagnosis("erasure read quorum");

        assert!(diagnosis.contains("Kubernetes snapshot collected"));
        assert!(!diagnosis.contains("RustFS"));
    }
}
