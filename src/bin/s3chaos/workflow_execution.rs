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
    fs,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use anyhow::{Context, Result, ensure};
use s3chaos::{
    fault::scenarios::{FaultBackend, scenario_spec},
    protocol::{
        mint::{MintTargetDiscovery, MintTargetSpec, MintTargetTimeouts},
        suite_plan::{ProtocolSuitePlan, TargetFingerprint},
        suite_runner::protocol_reproduction_suite,
    },
    workflow::{
        config::{Config, ProtocolTarget, Target},
        report, resources,
        runs::{self, RunRecord},
    },
};
use tokio::process::Command;

use super::{Kind, RunArgs, protocol_suite};

const MINT_IMAGE: &str =
    "minio/mint:edge@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200";

pub async fn run(
    configuration: &Path,
    data: &Path,
    args: RunArgs,
    reproduction: Option<(PathBuf, RunRecord)>,
) -> Result<()> {
    validate_arguments(&args)?;
    let (mut record, root) = RunRecord::create(
        data,
        args.kind.as_str(),
        &args.target,
        Target::default(),
        reproduction.as_ref().map(|(_, record)| record.id.clone()),
    )?;
    println!("Run: {}\nDirectory: {}", record.id, root.display());
    let outcome = async {
        record.target_config = match &reproduction {
            Some((_, original)) => original.target_config.clone(),
            None => Config::load(configuration)?.target(&args.target)?,
        };
        record.reproduction_image_override = args.use_current_image;
        record.suite = args.suite.clone();
        record.scenario = args.case.clone();
        record.qualification = args.qualification.clone();
        if let Some(fault) = &mut record.target_config.fault {
            // Persist the generated seed before any workload can start.
            fault
                .options
                .entry("RUSTFS_FAULT_TEST_SEED".into())
                .or_insert_with(|| {
                    u64::from_le_bytes(
                        uuid::Uuid::new_v4().as_bytes()[..8]
                            .try_into()
                            .expect("UUID has eight bytes"),
                    )
                    .to_string()
                });
        }
        record.save(&root)?;
        let bundled = resources::materialize(data)?;
        if matches!(args.kind, Kind::Fault)
            && let Some((original, _)) = &reproduction
            && original.join("suite.yaml").is_file()
            && let Some(selection) = &args.case
        {
            let (suite, seed) =
                s3chaos::workflow::fault_reproduction::select_attempt(original, selection)?;
            runs::write_file(
                &root.join("suite.yaml"),
                serde_yaml_ng::to_string(&suite)?.as_bytes(),
            )?;
            record
                .target_config
                .fault
                .as_mut()
                .context("missing fault target")?
                .options
                .insert("RUSTFS_FAULT_TEST_SEED".into(), seed.to_string());
            record.scenario = None;
            record.suite = Some("recorded-attempt".into());
        }
        let mut command = match args.kind {
            Kind::Fault => fault_command(
                &bundled,
                &root,
                &record,
                &args,
                reproduction.as_ref().map(|(root, _)| root.as_path()),
            )?,
            Kind::Protocol => protocol_command(
                &bundled,
                &root,
                &record,
                &args,
                reproduction.as_ref().map(|(root, _)| root.as_path()),
            )?,
            Kind::Mint => {
                mint_command(
                    &bundled,
                    &root,
                    &record,
                    args.namespace.as_deref(),
                    reproduction.as_ref().map(|(root, _)| root.as_path()),
                )
                .await?
            }
        };
        record.state = "running".into();
        record.result = "running".into();
        record.save(&root)?;
        wait_for_child(&mut command, Some((&root, &mut record))).await
    }
    .await;
    record.finished_at = Some(runs::timestamp()?);
    record.state = "finished".into();
    match outcome {
        Ok(status) => {
            record.exit_code = status.code().or(Some(130));
            record.result = if !status.success() {
                "failed"
            } else {
                match report::read_run_report(&root) {
                    Ok(report) => match report.artifact_result.as_deref() {
                        Some("passed") => "passed",
                        Some("failed") => "failed",
                        _ => "incomplete",
                    },
                    Err(error) => {
                        record.error = Some(redact_error(
                            &format!("read final evidence: {error:#}"),
                            &record.target_config,
                        ));
                        "incomplete"
                    }
                }
            }
            .into();
        }
        Err(error) => {
            record.exit_code = Some(1);
            record.result = "failed".into();
            record.error = Some(redact_error(&format!("{error:#}"), &record.target_config));
        }
    }
    record.save(&root)?;
    println!("Result: {}", record.result);
    if let Some(error) = &record.error {
        eprintln!("{error}");
    }
    print_next_steps(&root)?;
    ensure!(
        record.result == "passed",
        "run {} ended with {}; inspect its report",
        record.id,
        record.result
    );
    Ok(())
}

fn validate_arguments(args: &RunArgs) -> Result<()> {
    ensure!(
        !matches!(args.kind, Kind::Fault) || args.suite.is_none() || args.case.is_none(),
        "fault accepts either --suite or --case"
    );
    ensure!(
        matches!(args.kind, Kind::Mint) || args.namespace.is_none(),
        "--namespace is a Mint run option; fault namespaces belong in the saved target"
    );
    ensure!(
        matches!(args.kind, Kind::Fault) || args.qualification.is_none(),
        "--qualification requires fault"
    );
    ensure!(
        matches!(args.kind, Kind::Fault) || !args.keep_resources,
        "--keep-resources requires fault"
    );
    ensure!(
        !matches!(args.kind, Kind::Mint) || (args.suite.is_none() && args.case.is_none()),
        "Mint uses its recorded profile inventory, without --suite or --case"
    );
    Ok(())
}

fn fault_command(
    bundled: &Path,
    root: &Path,
    record: &RunRecord,
    args: &RunArgs,
    original: Option<&Path>,
) -> Result<Command> {
    let target = record
        .target_config
        .fault
        .as_ref()
        .context("target has no fault configuration; use init --kind fault")?;
    let mut environment = target.environment()?;
    environment.extend([
        ("S3CHAOS_RUN_ID".into(), record.id.clone()),
        (
            "S3CHAOS_RUN_ROOT".into(),
            root.join("artifacts").display().to_string(),
        ),
        (
            "S3CHAOS_BINARY".into(),
            std::env::current_exe()?.display().to_string(),
        ),
        (
            "RUSTFS_FAULT_TEST_RUN_ROOT".into(),
            root.join("artifacts").display().to_string(),
        ),
        ("RUSTFS_FAULT_TEST_DESTRUCTIVE".into(), "1".into()),
    ]);
    if args.keep_resources {
        environment.insert("S3CHAOS_KEEP_RESOURCES".into(), "1".into());
    }
    if args.case.as_deref() == Some("quorum-p-dm-eio") {
        let source = match original {
            Some(original) => original.join("quorum-dm-targets.json"),
            None => PathBuf::from(
                environment
                    .get("RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS")
                    .context("RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS is required")?,
            ),
        };
        let resolved = prepare_quorum_targets(&source, root)?;
        environment.insert(
            "RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS".into(),
            resolved.display().to_string(),
        );
    }
    let mut command = subprocess("bash", &environment);
    command.arg(bundled.join("scripts/fault-test.sh"));
    if root.join("suite.yaml").is_file() {
        command.arg("suite-run").arg(root.join("suite.yaml"));
    } else if let Some(qualification) = &args.qualification {
        command.args(["qualify", qualification]);
    } else if let Some(case) = &args.case {
        let spec = scenario_spec(case)?;
        command
            .arg(if spec.backend == FaultBackend::DeviceMapper {
                "dm-run"
            } else {
                "run"
            })
            .arg(case);
    } else {
        let suite = if let Some(original) = original {
            original.join("suite.yaml")
        } else {
            resources::suite_path(bundled, "fault", args.suite.as_deref().unwrap_or("smoke"))?
        };
        super::validate_suite(Kind::Fault, &suite)?;
        let snapshot = root.join("suite.yaml");
        runs::write_file(&snapshot, &fs::read(suite)?)?;
        command.arg("suite-run").arg(snapshot);
    }
    Ok(command)
}

fn prepare_quorum_targets(source: &Path, root: &Path) -> Result<PathBuf> {
    let template: serde_json::Value = runs::read_json(source)?;
    let mut resolved = template.clone();
    let targets = resolved
        .get_mut("targets")
        .and_then(serde_json::Value::as_array_mut)
        .context("quorum DM configuration requires a targets array")?;
    ensure!(targets.len() == 2, "quorum DM requires exactly two targets");
    for target in targets {
        let token = target["stateToken"]
            .as_str()
            .context("missing stateToken")?;
        let state_file = target["stateFile"].as_str().context("missing stateFile")?;
        if Path::new(state_file).is_relative() {
            ensure!(
                !token.is_empty()
                    && token.len() <= 128
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                    && state_file == format!(".host-mutation-{token}.json"),
                "relative stateFile must be .host-mutation-<stateToken>.json"
            );
            target["stateFile"] = serde_json::Value::String(
                root.join("artifacts")
                    .join(state_file)
                    .display()
                    .to_string(),
            );
        }
    }
    runs::write_json(&root.join("quorum-dm-targets.json"), &template)?;
    let path = root.join("quorum-dm-targets-resolved.json");
    runs::write_json(&path, &resolved)?;
    Ok(path)
}

fn protocol_command(
    bundled: &Path,
    root: &Path,
    record: &RunRecord,
    args: &RunArgs,
    original: Option<&Path>,
) -> Result<Command> {
    let target = record
        .target_config
        .protocol
        .as_ref()
        .context("target has no protocol configuration; use init --kind protocol")?;
    let mut environment = target.environment()?;
    let suite = if let Some(original) = original {
        let (suite, fingerprint) =
            protocol_reproduction_suite(original.join("artifacts"), args.case.as_deref())?;
        ensure!(
            target.fingerprint == fingerprint.sha256,
            "recorded target fingerprint does not match the original plan"
        );
        suite
    } else {
        let path = resources::suite_path(
            bundled,
            "protocol",
            args.suite.as_deref().unwrap_or("smoke"),
        )?;
        protocol_suite(&path, target, args.case.as_deref())?
    };
    let snapshot = root.join("suite.yaml");
    runs::write_file(&snapshot, serde_yaml_ng::to_string(&suite)?.as_bytes())?;
    environment.insert(
        "RUSTFS_PROTOCOL_TEST_RUN_ROOT".into(),
        root.join("artifacts").display().to_string(),
    );
    let mut command = worker(&environment)?;
    command.arg("protocol-suite-run").arg(snapshot);
    Ok(command)
}

async fn discover_mint(
    root: &Path,
    target: &Target,
    namespace: Option<&str>,
) -> Result<(MintTargetSpec, BTreeMap<String, String>)> {
    let profile = target
        .mint
        .as_ref()
        .context("target has no Mint configuration; use init --kind mint")?;
    let namespace = namespace.context("Mint requires --namespace for a prepared ephemeral target; its namespace will be deleted after testing")?;
    let mut environment = profile.credentials.environment()?;
    environment.insert("RUSTFS_PROTOCOL_TEST_DEDICATED".into(), "1".into());
    let request = MintTargetDiscovery {
        context: profile.context.clone(),
        namespace: namespace.into(),
        service_name: profile.service.clone(),
        server_endpoint: profile.endpoint.clone(),
        service_port: profile.port,
        enable_https: profile
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.starts_with("https://")),
        region: profile.region.clone(),
        rustfs_container: profile.container.clone(),
        timeouts: MintTargetTimeouts::default(),
    };
    let request_path = root.join("mint-discovery.json");
    runs::write_json(&request_path, &request)?;
    let output = capture(
        worker(&environment)?
            .arg("workflow-mint-discover")
            .arg(&request_path),
    )
    .await?;
    let spec: MintTargetSpec =
        serde_json::from_slice(&output).context("parse verified Mint target")?;
    runs::write_file(
        &root.join("mint-target.yaml"),
        serde_yaml_ng::to_string(&spec)?.as_bytes(),
    )?;
    Ok((spec, environment))
}

async fn mint_command(
    bundled: &Path,
    root: &Path,
    record: &RunRecord,
    namespace: Option<&str>,
    original: Option<&Path>,
) -> Result<Command> {
    let (_, mut environment) = discover_mint(root, &record.target_config, namespace).await?;
    if let Some(original) = original {
        let mut command = worker(&environment)?;
        command
            .arg("workflow-mint-reproduce")
            .arg(original.join("artifacts"))
            .arg(root.join("mint-target.yaml"))
            .arg(root.join("artifacts"));
        return Ok(command);
    }
    for name in [
        "aws-sdk-php-core-inventory.yaml",
        "aws-sdk-php-core-known-failures.yaml",
    ] {
        runs::write_file(
            &root.join(name),
            &fs::read(bundled.join("protocol/mint").join(name))?,
        )?;
    }
    environment.extend([
        (
            "RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE".into(),
            MINT_IMAGE.into(),
        ),
        (
            "RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM".into(),
            "linux/amd64".into(),
        ),
        ("RUSTFS_PROTOCOL_COMPAT_MINT_MODE".into(), "core".into()),
        (
            "RUSTFS_PROTOCOL_COMPAT_MINT_SUITES".into(),
            "aws-sdk-php".into(),
        ),
        (
            "RUSTFS_PROTOCOL_COMPAT_PROFILE_NAME".into(),
            "rustfs-mint-core".into(),
        ),
    ]);
    let mut command = worker(&environment)?;
    command
        .arg("protocol-mint-run")
        .arg(root.join("mint-target.yaml"))
        .arg(root.join("aws-sdk-php-core-inventory.yaml"))
        .arg(root.join("aws-sdk-php-core-known-failures.yaml"))
        .arg(root.join("artifacts"));
    Ok(command)
}

pub async fn reproduce(
    data: &Path,
    id: &str,
    case: Option<String>,
    namespace: Option<String>,
    use_current_version: bool,
    use_current_image: bool,
) -> Result<()> {
    let root = runs::resolve_run(data, id)?;
    let mut original = RunRecord::load(&root)?;
    ensure!(
        original.state == "finished",
        "run is still active or its completion is unknown; inspect the run before reproducing"
    );
    ensure!(
        use_current_version
            || (original.source_revision == env!("S3CHAOS_BUILD_REVISION")
                && original.tool_version == env!("CARGO_PKG_VERSION")),
        "S3Chaos version differs from this run; pass --use-current-version to record this difference"
    );
    let kind = Kind::parse(&original.kind)?;
    if matches!(kind, Kind::Fault)
        && let Some(case) = &case
    {
        if let Some(recorded) = &original.scenario {
            ensure!(
                recorded == case,
                "requested scenario was not part of the original run"
            );
        } else {
            ensure!(
                root.join("suite.yaml").is_file(),
                "original run has no fault suite to select from"
            );
        }
    }
    if let Some(target) = original
        .target_config
        .fault
        .as_mut()
        .filter(|_| matches!(kind, Kind::Fault))
    {
        if let Some(image) = recorded_fault_image(&root, &target.image)? {
            target.image = image;
        } else {
            ensure!(
                use_current_image,
                "original run has no pullable image digest; pass --use-current-image to acknowledge using its saved image tag"
            );
        }
    }
    let args = RunArgs {
        kind,
        target: original.target.clone(),
        suite: if matches!(kind, Kind::Fault) && case.is_some() {
            None
        } else {
            original.suite.clone()
        },
        case: case.or_else(|| original.scenario.clone()),
        qualification: original.qualification.clone(),
        namespace,
        keep_resources: false,
        use_current_image,
    };
    run(Path::new(""), data, args, Some((root, original))).await
}

fn recorded_fault_image(root: &Path, requested: &str) -> Result<Option<String>> {
    if pullable_digest(requested) {
        return Ok(Some(requested.into()));
    }
    let path = root.join("artifacts/fault-image.json");
    if !path.exists() {
        return Ok(None);
    }
    let evidence: serde_json::Value = runs::read_json(&path)?;
    ensure!(
        evidence["requestedImage"] == requested,
        "recorded image evidence differs from the target snapshot"
    );
    let Some(containers) = evidence["containers"]
        .as_array()
        .filter(|values| !values.is_empty())
    else {
        return Ok(None);
    };
    let mut digest = None;
    for container in containers {
        let Some(identity) = container["imageID"].as_str() else {
            return Ok(None);
        };
        let identity = identity
            .strip_prefix("docker-pullable://")
            .or_else(|| identity.strip_prefix("containerd://"))
            .unwrap_or(identity);
        if !pullable_digest(identity)
            || digest.as_ref().is_some_and(|previous| previous != identity)
        {
            return Ok(None);
        }
        digest = Some(identity.to_owned());
    }
    Ok(digest)
}

fn pullable_digest(image: &str) -> bool {
    image
        .rsplit_once("@sha256:")
        .is_some_and(|(repository, digest)| {
            !repository.is_empty()
                && !repository.contains("://")
                && !repository.chars().any(char::is_whitespace)
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

pub async fn cleanup(data: &Path, id: &str) -> Result<()> {
    let root = runs::resolve_run(data, id)?;
    let record = RunRecord::load(&root)?;
    ensure!(
        record
            .worker_process
            .as_ref()
            .and_then(|process| process.is_running())
            != Some(true),
        "the recorded worker is still active; stop the supervisor before cleanup"
    );
    ensure!(
        record.state == "finished"
            || (record
                .process
                .as_ref()
                .and_then(|process| process.is_running())
                == Some(false)
                && record
                    .worker_process
                    .as_ref()
                    .and_then(|process| process.is_running())
                    == Some(false)),
        "the original supervisor may still be active; stop it and confirm restoration on its host before cleanup"
    );
    let kind = Kind::parse(&record.kind)?;
    let environment = match kind {
        Kind::Fault => record
            .target_config
            .fault
            .as_ref()
            .context("missing fault target snapshot")?
            .environment()?,
        Kind::Protocol => record
            .target_config
            .protocol
            .as_ref()
            .context("missing protocol target snapshot")?
            .environment()?,
        Kind::Mint => record
            .target_config
            .mint
            .as_ref()
            .context("missing Mint target snapshot")?
            .credentials
            .recovery_environment()?,
    };
    let mut environment = environment;
    environment.insert("RUSTFS_PROTOCOL_TEST_DEDICATED".into(), "1".into());
    let mut command = worker(&environment)?;
    command
        .arg(match kind {
            Kind::Fault => "fault-workflow-cleanup",
            Kind::Protocol => "protocol-cleanup",
            Kind::Mint => "protocol-mint-cleanup",
        })
        .arg(root.join("artifacts"));
    let status = wait_for_child(&mut command, None).await?;
    ensure!(
        status.success(),
        "cleanup is incomplete; retain the run directory and inspect its cleanup evidence"
    );
    println!("Cleanup completed for {}", record.id);
    Ok(())
}

pub async fn doctor(
    configuration: &Path,
    data: &Path,
    name: &str,
    kind: Kind,
    case: Option<&str>,
    namespace: Option<&str>,
    suite: Option<&str>,
) -> Result<()> {
    ensure!(
        matches!(kind, Kind::Protocol) || suite.is_none(),
        "doctor --suite requires protocol"
    );
    ensure!(
        !matches!(kind, Kind::Mint) || case.is_none(),
        "Mint uses its profile inventory without --case"
    );
    let target = Config::load(configuration)?.target(name)?;
    match kind {
        Kind::Fault => {
            let profile = target
                .fault
                .as_ref()
                .context("target has no fault configuration")?;
            let mut environment = profile.environment()?;
            environment.insert(
                "S3CHAOS_BINARY".into(),
                std::env::current_exe()?.display().to_string(),
            );
            let bundled = resources::materialize(data)?;
            let mut command = subprocess("bash", &environment);
            command
                .arg(bundled.join("scripts/fault-test.sh"))
                .arg("preflight")
                .arg(case.unwrap_or("pod-kill-one"));
            ensure!(
                wait_for_child(&mut command, None).await?.success(),
                "fault prerequisites are incomplete"
            );
        }
        Kind::Protocol => {
            let profile = target
                .protocol
                .as_ref()
                .context("target has no protocol configuration")?;
            let fingerprint =
                inspect_protocol_suite(data, profile, suite.unwrap_or("smoke"), case).await?;
            ensure!(
                fingerprint.sha256 == profile.fingerprint,
                "target identity changed; review the deployment and update its configuration with init --replace"
            );
            println!("Verified deployment {}", fingerprint.deployment_id);
        }
        Kind::Mint => {
            let directory = temporary_directory(data)?;
            let result = discover_mint(&directory, &target, namespace).await;
            let _ = fs::remove_dir_all(&directory);
            let (spec, _) = result?;
            println!("Verified ephemeral namespace {}", spec.namespace);
        }
    }
    println!("{name}: prerequisites passed");
    Ok(())
}

pub async fn inspect_protocol_target(
    data: &Path,
    profile: &ProtocolTarget,
) -> Result<TargetFingerprint> {
    inspect_protocol_suite(data, profile, "smoke", None).await
}

async fn inspect_protocol_suite(
    data: &Path,
    profile: &ProtocolTarget,
    selection: &str,
    case: Option<&str>,
) -> Result<TargetFingerprint> {
    let bundled = resources::materialize(data)?;
    let directory = temporary_directory(data)?;
    let result = async {
        let suite = protocol_suite(
            &resources::suite_path(&bundled, "protocol", selection)?,
            profile,
            case,
        )?;
        let path = directory.join("suite.yaml");
        runs::write_file(&path, serde_yaml_ng::to_string(&suite)?.as_bytes())?;
        let output = capture(
            worker(&profile.environment()?)?
                .arg("protocol-suite-plan")
                .arg(path),
        )
        .await?;
        let plan: ProtocolSuitePlan =
            serde_json::from_slice(&output).context("parse protocol preflight")?;
        check_protocol_capabilities(
            &plan.preflight.capability_matrix,
            plan.preflight.mutating_permission_probe.status,
            profile,
        )?;
        ensure!(
            !plan
                .target
                .fingerprint
                .deployment_id
                .starts_with("s3-endpoint:"),
            "target did not provide a verified RustFS deployment identity"
        );
        Ok(plan.target.fingerprint)
    }
    .await;
    let _ = fs::remove_dir_all(directory);
    result
}

fn check_protocol_capabilities(
    checks: &[s3chaos::protocol::catalog::ProtocolCapabilityCheck],
    probe: s3chaos::protocol::suite_plan::ProtocolMutatingProbeStatus,
    profile: &ProtocolTarget,
) -> Result<()> {
    use s3chaos::protocol::{
        catalog::ProtocolCapabilityState, suite_plan::ProtocolMutatingProbeStatus,
    };
    let target = Target {
        protocol: Some(profile.clone()),
        ..Default::default()
    };
    let failed = checks
        .iter()
        .filter(|check| check.state == ProtocolCapabilityState::Fail)
        .map(|check| {
            format!(
                "{}: {}",
                check.capability,
                redact_error(&check.reason, &target)
            )
        })
        .collect::<Vec<_>>();
    ensure!(
        failed.is_empty(),
        "target capability checks failed: {}",
        failed.join("; ")
    );
    for check in checks
        .iter()
        .filter(|check| check.state == ProtocolCapabilityState::Skip)
    {
        eprintln!(
            "Not verified: {} ({})",
            check.capability,
            redact_error(&check.reason, &target)
        );
    }
    if probe == ProtocolMutatingProbeStatus::NotRun {
        eprintln!("Mutation permissions will be verified during execution.");
    }
    Ok(())
}

fn temporary_directory(data: &Path) -> Result<PathBuf> {
    let path = data
        .join("temporary")
        .join(uuid::Uuid::new_v4().to_string());
    runs::private_directory(&path)?;
    Ok(path.canonicalize()?)
}

fn worker(environment: &BTreeMap<String, String>) -> Result<Command> {
    Ok(subprocess(std::env::current_exe()?, environment))
}

fn subprocess(
    program: impl AsRef<std::ffi::OsStr>,
    environment: &BTreeMap<String, String>,
) -> Command {
    let mut command = Command::new(program);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("RUSTFS_FAULT_TEST_")
            || name.starts_with("RUSTFS_PROTOCOL_")
            || name.starts_with("S3CHAOS_")
        {
            command.env_remove(key);
        }
    }
    command.envs(environment);
    command.env("S3CHAOS_SOURCE_REVISION", env!("S3CHAOS_BUILD_REVISION"));
    command
}

async fn capture(command: &mut Command) -> Result<Vec<u8>> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .await
        .context("start read-only preflight")?;
    ensure!(
        output.status.success(),
        "preflight failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

async fn wait_for_child(
    command: &mut Command,
    record: Option<(&Path, &mut RunRecord)>,
) -> Result<ExitStatus> {
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = {
        use tokio::signal::unix::{SignalKind, signal};
        command.process_group(0);
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
        )
    };
    let mut child = command.spawn().context("start test supervisor")?;
    if let Some((root, record)) = record {
        record.worker_process = child.id().and_then(runs::ProcessIdentity::for_pid);
        if let Err(error) = record.save(root) {
            if let Some(pid) = child.id() {
                let _ = forward_termination(pid).await;
            }
            let _ = child.wait().await;
            return Err(error.context("persist worker identity"));
        }
    }
    #[cfg(unix)]
    {
        let mut requested = false;
        loop {
            tokio::select! {
                status = child.wait() => return status.context("wait for test supervisor"),
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            if !requested {
                eprintln!("Stopping test; waiting for restoration and evidence publication...");
                if let Some(pid) = child.id() {
                    if let Err(error) = forward_termination(pid).await {
                        eprintln!("Cannot signal test supervisor: {error}; waiting for completion");
                    } else {
                        requested = true;
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        child.wait().await.context("wait for test supervisor")
    }
}

async fn forward_termination(pid: u32) -> Result<()> {
    let status = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await?;
    ensure!(status.success(), "supervisor did not accept SIGTERM");
    Ok(())
}

fn redact_error(error: &str, target: &Target) -> String {
    let mut result = error.to_owned();
    let mut sources = Vec::new();
    for credentials in [
        target.protocol.as_ref().map(|target| &target.credentials),
        target.mint.as_ref().map(|target| &target.credentials),
    ]
    .into_iter()
    .flatten()
    {
        sources.extend(
            [
                Some(&credentials.access_key_env),
                Some(&credentials.secret_key_env),
                credentials.session_token_env.as_ref(),
            ]
            .into_iter()
            .flatten(),
        );
    }
    if let Some(profile) = &target.protocol {
        sources.extend(profile.oidc.values());
    }
    let mut secrets = sources
        .into_iter()
        .filter_map(|source| std::env::var(source).ok())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for secret in secrets {
        result = result.replace(&secret, "[REDACTED]");
    }
    result.truncate(result.floor_char_boundary(8192));
    result
}

pub fn print_next_steps(root: &Path) -> Result<()> {
    let binary = std::env::current_exe()?;
    println!(
        "Report: {} report {}\nReproduce: {} reproduce {}\nCleanup: {} cleanup {}",
        shell_argument(&binary),
        shell_argument(root),
        shell_argument(&binary),
        shell_argument(root),
        shell_argument(&binary),
        shell_argument(root)
    );
    Ok(())
}

fn shell_argument(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3chaos::protocol::{
        catalog::{
            ProtocolCapability, ProtocolCapabilityCheck, ProtocolCapabilitySource,
            ProtocolCapabilityState,
        },
        suite_plan::ProtocolMutatingProbeStatus,
    };

    fn protocol_target() -> ProtocolTarget {
        ProtocolTarget {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            fingerprint: "a".repeat(64),
            credentials: Default::default(),
            oidc: Default::default(),
        }
    }

    #[test]
    fn doctor_rejects_a_failed_external_identity_check() {
        let check = ProtocolCapabilityCheck {
            capability: ProtocolCapability::Oidc,
            source: ProtocolCapabilitySource::External,
            state: ProtocolCapabilityState::Fail,
            reason: "issuer is unavailable".into(),
        };
        let error = check_protocol_capabilities(
            &[check],
            ProtocolMutatingProbeStatus::NotRun,
            &protocol_target(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("issuer is unavailable"));
        assert!(
            check_protocol_capabilities(
                &[],
                ProtocolMutatingProbeStatus::NotRun,
                &protocol_target()
            )
            .is_ok()
        );
    }

    #[test]
    fn quorum_targets_preserve_absolute_paths_and_reject_relative_escapes() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("targets.json");
        let root = directory.path().join("run");
        let absolute = directory.path().join("existing-state.json");
        fs::write(&absolute, b"existing recovery evidence").unwrap();
        let mut template = serde_json::json!({"targets": [
            {"stateFile": absolute, "stateToken": "a"},
            {"stateFile": ".host-mutation-b.json", "stateToken": "b"}
        ]});
        runs::write_json(&source, &template).unwrap();
        let path = prepare_quorum_targets(&source, &root).unwrap();
        let resolved: serde_json::Value = runs::read_json(&path).unwrap();
        assert_eq!(
            resolved["targets"][0]["stateFile"],
            template["targets"][0]["stateFile"]
        );
        assert_eq!(fs::read(&absolute).unwrap(), b"existing recovery evidence");
        for invalid in [
            "../.host-mutation-b.json",
            "nested/.host-mutation-b.json",
            ".host-mutation-other.json",
        ] {
            template["targets"][1]["stateFile"] = invalid.into();
            runs::write_json(&source, &template).unwrap();
            assert!(prepare_quorum_targets(&source, &root).is_err());
        }
        for invalid in [
            serde_json::json!(null),
            serde_json::json!({"targets": "invalid"}),
        ] {
            runs::write_json(&source, &invalid).unwrap();
            assert!(prepare_quorum_targets(&source, &root).is_err());
        }
    }

    #[test]
    fn image_reproduction_requires_a_pullable_consistent_digest() {
        let root = tempfile::tempdir().unwrap();
        let requested = "rustfs/rustfs:latest";
        assert!(
            recorded_fault_image(root.path(), requested)
                .unwrap()
                .is_none()
        );
        let pinned = format!("rustfs/rustfs@sha256:{}", "a".repeat(64));
        assert_eq!(
            recorded_fault_image(root.path(), &pinned).unwrap(),
            Some(pinned.clone())
        );
        let path = root.path().join("artifacts/fault-image.json");
        let evidence = |identities: &[String]| serde_json::json!({"requestedImage": requested, "containers": identities.iter().map(|id| serde_json::json!({"image": requested, "imageID": id})).collect::<Vec<_>>()});
        runs::write_json(&path, &evidence(&[format!("docker-pullable://{pinned}")])).unwrap();
        assert_eq!(
            recorded_fault_image(root.path(), requested).unwrap(),
            Some(pinned.clone())
        );
        runs::write_json(
            &path,
            &evidence(&[format!("containerd://sha256:{}", "a".repeat(64))]),
        )
        .unwrap();
        assert!(
            recorded_fault_image(root.path(), requested)
                .unwrap()
                .is_none()
        );
        runs::write_json(
            &path,
            &evidence(&[pinned, format!("rustfs/rustfs@sha256:{}", "b".repeat(64))]),
        )
        .unwrap();
        assert!(
            recorded_fault_image(root.path(), requested)
                .unwrap()
                .is_none()
        );
    }
}
