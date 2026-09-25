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
#[path = "s3chaos/console_server.rs"]
mod console_server;

use console_server::serve_console;
use s3chaos::fault::{
    artifact_validation::{ArtifactValidationOptions, validate_fault_artifacts_and_write_report},
    console::build_console_snapshot,
    runner::run_selected_scenario_from_env,
    scenarios::{planned_qualification_catalog_json, scenario_catalog_json},
    shutdown::run_signal_aware,
    spec::{FaultRunArtifactSpec, FaultRunSpec},
    suite::{fault_suite_template_yaml, resolve_fault_suite_yaml},
    suite_plan::plan_fault_suite_from_yaml,
    suite_runner::run_fault_suite_from_yaml,
};
use s3chaos::protocol::{
    artifact_validation::validate_protocol_artifacts_and_write_report,
    catalog::protocol_catalog_json,
    mint::{
        MintCapturedRun, MintInfrastructureFailure, MintInventory, MintKnownFailures, MintMode,
        MintProfile, MintProfileSpec, MintSessionRequest, MintTargetSpec, cleanup_mint_session,
        run_mint_session, timestamp_now, validate_mint_artifacts_and_write_report,
        validate_mint_session_artifacts_and_write_report, verify_mint_target, write_mint_artifacts,
    },
    suite::{
        ProtocolExecutionProfile, protocol_suite_template_yaml, resolve_protocol_suite_yaml,
        validate_protocol_ci_environment, validate_protocol_execution_profile_as,
    },
    suite_runner::{
        cleanup_protocol_artifact_root, cleanup_protocol_registry_path,
        plan_protocol_suite_from_yaml, reproduce_protocol_case_from_artifacts,
        run_protocol_suite_from_yaml,
    },
};
use std::{fs, io::ErrorKind, net::SocketAddr, path::Path};

const MAX_MINT_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "help" | "--help" | "-h" => print_help(),
        "fault-catalog-json" => print_fault_catalog_json(),
        "fault-qualification-catalog-json" => print_fault_qualification_catalog_json(),
        "fault-console-json" => print_fault_console_json(args),
        "fault-console-serve" => serve_fault_console(args).await,
        "fault-required-artifacts-json" => print_fault_required_artifacts_json(),
        "fault-run" => run_signal_aware(run_selected_scenario_from_env()).await,
        "fault-suite-json" => print_fault_suite_json(args),
        "fault-suite-plan" => print_fault_suite_plan(args),
        "fault-suite-run" => run_signal_aware(run_fault_suite(args)).await,
        "fault-suite-template" => print_fault_suite_template(),
        "fault-suite-validate" => validate_fault_suite(args),
        "fault-ack-calibration-analyze" => analyze_ack_calibration(args),
        "fault-validate-artifacts" => validate_fault_artifacts_command(args),
        "fault-run-spec-equal" => validate_fault_run_spec_equivalence(args),
        "protocol-catalog-json" => print_protocol_catalog_json(),
        "protocol-mint-evaluate" => evaluate_mint_artifacts(args),
        "protocol-mint-run" => run_mint_session_command(args).await,
        "protocol-mint-cleanup" => cleanup_mint_session_command(args).await,
        "protocol-mint-verify-target" => verify_mint_target_command(args).await,
        "protocol-mint-validate-artifacts" => validate_mint_artifacts(args),
        "protocol-mint-validate-session" => validate_mint_session_artifacts(args),
        "protocol-cleanup" => cleanup_protocol_artifacts(args).await,
        "protocol-ci-profile-validate" => validate_protocol_ci_profile(args),
        "protocol-suite-json" => print_protocol_suite_json(args),
        "protocol-suite-plan" => print_protocol_suite_plan(args).await,
        "protocol-suite-reproduce" => reproduce_protocol_case(args).await,
        "protocol-suite-run" => run_protocol_suite(args).await,
        "protocol-suite-template" => print_protocol_suite_template(),
        "protocol-suite-validate" => validate_protocol_suite(args),
        "protocol-validate-artifacts" => validate_protocol_artifacts(args),
        unknown => bail!("unknown s3chaos command: {unknown}; run `s3chaos help`"),
    }
}

fn print_help() -> Result<()> {
    println!("S3Chaos fault-test helper");
    println!();
    println!("Commands:");
    println!("  fault-catalog-json");
    println!("  fault-qualification-catalog-json");
    println!("  fault-console-json <artifact-root>");
    println!("  fault-console-serve <artifact-root> [--addr 127.0.0.1:0] [--allow-non-loopback]");
    println!("  fault-required-artifacts-json");
    println!("  fault-run");
    println!("  fault-suite-json <suite.yaml>");
    println!("  fault-suite-plan <suite.yaml>");
    println!("  fault-suite-run <suite.yaml>");
    println!("  fault-suite-template");
    println!("  fault-suite-validate <suite.yaml>");
    println!("  fault-ack-calibration-analyze <strict-suite-root> <relaxed-suite-root>");
    println!("  fault-validate-artifacts <scenario> <artifact-root> [--validation-summary-tsv]");
    println!("  fault-run-spec-equal <run-spec.json> <run-spec.yaml>");
    println!("  protocol-catalog-json");
    println!(
        "  protocol-mint-evaluate <inventory.yaml> <known-failures.yaml> <log.json> <stdout.log> <stderr.log> <container-exit-code> <verified-target-fingerprint> <evaluated-at> <artifact-root>"
    );
    println!(
        "  protocol-mint-run <target.yaml> <inventory.yaml> <known-failures.yaml> <artifact-root>"
    );
    println!("  protocol-mint-cleanup <artifact-root>");
    println!("  protocol-mint-verify-target");
    println!("  protocol-mint-validate-artifacts <artifact-root>");
    println!("  protocol-mint-validate-session <artifact-root>");
    println!("  protocol-cleanup <artifact-root>");
    println!("  protocol-cleanup --registry <resource-registry.json>");
    println!("  protocol-ci-profile-validate <smoke|full|slow|external> <suite.yaml>");
    println!("  protocol-suite-json <suite.yaml>");
    println!("  protocol-suite-plan <suite.yaml>");
    println!("  protocol-suite-reproduce <artifact-root> <case-id>");
    println!("  protocol-suite-run <suite.yaml>");
    println!("  protocol-suite-template");
    println!("  protocol-suite-validate <suite.yaml>");
    println!("  protocol-validate-artifacts <artifact-root>");
    Ok(())
}

async fn run_mint_session_command(mut args: impl Iterator<Item = String>) -> Result<()> {
    let target_path = next_arg(&mut args, "Mint ephemeral target path")?;
    let inventory_path = next_arg(&mut args, "Mint inventory path")?;
    let known_failures_path = next_arg(&mut args, "Mint known-failures path")?;
    let artifact_root = next_arg(&mut args, "Mint session artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-mint-run accepts exactly four arguments"
    );
    let target = MintTargetSpec::from_yaml(
        &fs::read_to_string(&target_path)
            .with_context(|| format!("read Mint ephemeral target {target_path}"))?,
        &timestamp_now()?,
    )?;
    let inventory = MintInventory::from_yaml(
        &fs::read_to_string(&inventory_path)
            .with_context(|| format!("read Mint inventory {inventory_path}"))?,
    )?;
    let known_failures = MintKnownFailures::from_yaml(
        &fs::read_to_string(&known_failures_path)
            .with_context(|| format!("read Mint known failures {known_failures_path}"))?,
    )?;
    let mode = required_env("RUSTFS_PROTOCOL_COMPAT_MINT_MODE")?.parse::<MintMode>()?;
    let suites = required_env("RUSTFS_PROTOCOL_COMPAT_MINT_SUITES")?
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let publication = run_mint_session(MintSessionRequest {
        artifact_root: artifact_root.into(),
        target,
        profile_name: std::env::var("RUSTFS_PROTOCOL_COMPAT_PROFILE_NAME")
            .unwrap_or_else(|_| "rustfs-mint-core".to_string()),
        mint_image: required_env("RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE")?,
        mint_platform: required_env("RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM")?,
        mint_mode: mode,
        mint_suites: suites,
        inventory,
        known_failures,
        forbidden_material: mint_forbidden_material(),
    })
    .await?;
    print!("{}", publication.terminal_summary);
    ensure!(
        publication.gate_exit_code == 0,
        "Mint session gate failed; inspect {}",
        publication.artifact_root.display()
    );
    Ok(())
}

async fn cleanup_mint_session_command(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = next_arg(&mut args, "Mint session artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-mint-cleanup accepts exactly one argument"
    );
    let publication = cleanup_mint_session(&artifact_root, &mint_forbidden_material()).await?;
    print!("{}", publication.terminal_summary);
    ensure!(
        publication.cleanup_exit_code == 0,
        "Mint recovery cleanup failed; inspect {artifact_root}"
    );
    Ok(())
}

fn validate_mint_session_artifacts(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = next_arg(&mut args, "Mint session artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-mint-validate-session accepts exactly one argument"
    );
    let report = validate_mint_session_artifacts_and_write_report(
        &artifact_root,
        &mint_forbidden_material(),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn reproduce_protocol_case(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = args
        .next()
        .context("protocol-suite-reproduce requires artifact root")?;
    let case_id = args
        .next()
        .context("protocol-suite-reproduce requires case id")?;
    ensure!(
        args.next().is_none(),
        "protocol-suite-reproduce accepts exactly one artifact root and case id"
    );
    reproduce_protocol_case_from_artifacts(artifact_root, &case_id).await
}

fn validate_protocol_ci_profile(mut args: impl Iterator<Item = String>) -> Result<()> {
    validate_protocol_ci_environment()?;
    let profile = args
        .next()
        .context("protocol-ci-profile-validate requires profile")?
        .parse::<ProtocolExecutionProfile>()?;
    let suite = args
        .next()
        .context("protocol-ci-profile-validate requires suite path")?;
    ensure!(
        args.next().is_none(),
        "protocol-ci-profile-validate accepts exactly one profile and suite path"
    );
    let suite = resolve_protocol_suite_yaml(suite)?;
    validate_protocol_execution_profile_as(&suite, Some(profile))?;
    println!("validated {profile} protocol profile");
    Ok(())
}

fn validate_protocol_artifacts(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = args
        .next()
        .context("protocol-validate-artifacts requires artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-validate-artifacts accepts exactly one artifact root"
    );
    let forbidden = [
        "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY",
        "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY",
        "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN",
        "RUSTFS_PROTOCOL_OIDC_CLIENT_SECRET",
        "RUSTFS_PROTOCOL_OIDC_ADMIN_PASSWORD",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok())
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>();
    let report = validate_protocol_artifacts_and_write_report(artifact_root, &forbidden)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn cleanup_protocol_artifacts(mut args: impl Iterator<Item = String>) -> Result<()> {
    let first = args
        .next()
        .context("protocol-cleanup requires artifact root or --registry")?;
    if first == "--registry" {
        let registry = args
            .next()
            .context("protocol-cleanup --registry requires registry path")?;
        ensure!(
            args.next().is_none(),
            "protocol-cleanup --registry accepts exactly one registry path"
        );
        return cleanup_protocol_registry_path(registry).await;
    }
    ensure!(
        args.next().is_none(),
        "protocol-cleanup accepts exactly one artifact root"
    );
    cleanup_protocol_artifact_root(first).await
}

fn print_protocol_catalog_json() -> Result<()> {
    println!("{}", protocol_catalog_json()?);
    Ok(())
}

fn evaluate_mint_artifacts(mut args: impl Iterator<Item = String>) -> Result<()> {
    let inventory_path = next_arg(&mut args, "Mint inventory path")?;
    let known_failures_path = next_arg(&mut args, "Mint known-failures path")?;
    let log_path = next_arg(&mut args, "Mint log path")?;
    let stdout_path = next_arg(&mut args, "Mint stdout path")?;
    let stderr_path = next_arg(&mut args, "Mint stderr path")?;
    let container_exit_code = next_arg(&mut args, "Mint container exit code")?
        .parse::<i32>()
        .context("parse Mint container exit code")?;
    let target_fingerprint = next_arg(&mut args, "verified Mint target fingerprint")?;
    let evaluated_at = next_arg(&mut args, "Mint evaluation timestamp")?;
    let artifact_root = next_arg(&mut args, "Mint artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-mint-evaluate accepts exactly nine arguments"
    );

    let inventory = MintInventory::from_yaml(
        &fs::read_to_string(&inventory_path)
            .with_context(|| format!("read Mint inventory {inventory_path}"))?,
    )?;
    let known_failures = MintKnownFailures::from_yaml(
        &fs::read_to_string(&known_failures_path)
            .with_context(|| format!("read Mint known failures {known_failures_path}"))?,
    )?;
    let mode = required_env("RUSTFS_PROTOCOL_COMPAT_MINT_MODE")?.parse::<MintMode>()?;
    let suites = required_env("RUSTFS_PROTOCOL_COMPAT_MINT_SUITES")?
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let region = required_env("RUSTFS_PROTOCOL_COMPAT_REGION")?;
    let expected_fingerprint = required_env("RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT")?;
    validate_verified_mint_target_fingerprint(&target_fingerprint, &expected_fingerprint)?;
    let profile = MintProfile::new(MintProfileSpec {
        name: std::env::var("RUSTFS_PROTOCOL_COMPAT_PROFILE_NAME")
            .unwrap_or_else(|_| "rustfs-mint-core".to_string()),
        image: required_env("RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE")?,
        platform: required_env("RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM")?,
        mode,
        suites,
        region,
        target_fingerprint,
    })?;
    let log = read_optional_bounded_file(Path::new(&log_path), "Mint log")?;
    let stdout = read_bounded_file(Path::new(&stdout_path), "captured Mint stdout")?;
    let stderr = read_bounded_file(Path::new(&stderr_path), "captured Mint stderr")?;
    let infrastructure_failure = mint_infrastructure_failure(container_exit_code);
    let container_started =
        infrastructure_failure != Some(MintInfrastructureFailure::ContainerStart);
    let forbidden = mint_forbidden_material();
    let publication = write_mint_artifacts(
        &artifact_root,
        &profile,
        &inventory,
        &known_failures,
        MintCapturedRun {
            container_started,
            container_exit_code: Some(container_exit_code),
            infrastructure_failure,
            log: log.as_deref(),
            stdout: &stdout,
            stderr: &stderr,
        },
        &evaluated_at,
        &forbidden,
    )?;
    print!("{}", publication.terminal_summary);
    println!("artifacts: {artifact_root}");
    ensure!(
        publication.gate_exit_code == 0,
        "Mint gate failed; inspect {artifact_root}"
    );
    Ok(())
}

async fn verify_mint_target_command(mut args: impl Iterator<Item = String>) -> Result<()> {
    ensure!(
        args.next().is_none(),
        "protocol-mint-verify-target accepts no arguments"
    );
    let region = required_env("RUSTFS_PROTOCOL_COMPAT_REGION")?;
    let fingerprint = verify_mint_target_from_env(&region).await?;
    println!("{fingerprint}");
    Ok(())
}

async fn verify_mint_target_from_env(region: &str) -> Result<String> {
    let enable_https = match std::env::var("RUSTFS_PROTOCOL_COMPAT_ENABLE_HTTPS")
        .unwrap_or_else(|_| "0".to_string())
        .as_str()
    {
        "0" => false,
        "1" => true,
        value => bail!("RUSTFS_PROTOCOL_COMPAT_ENABLE_HTTPS must be 0 or 1, got {value:?}"),
    };
    verify_mint_target(
        &required_env("RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT")?,
        enable_https,
        region,
        &required_env("RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT")?,
    )
    .await
}

fn validate_verified_mint_target_fingerprint(verified: &str, expected: &str) -> Result<()> {
    ensure!(
        verified == format!("sha256:{expected}"),
        "verified Mint target fingerprint disagrees with RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT"
    );
    Ok(())
}

fn validate_mint_artifacts(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = next_arg(&mut args, "Mint artifact root")?;
    ensure!(
        args.next().is_none(),
        "protocol-mint-validate-artifacts accepts exactly one argument"
    );
    let report =
        validate_mint_artifacts_and_write_report(&artifact_root, &mint_forbidden_material())?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next().with_context(|| format!("missing {name}"))
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    ensure!(!value.trim().is_empty(), "{name} must not be empty");
    Ok(value)
}

fn mint_forbidden_material() -> Vec<String> {
    [
        "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY",
        "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY",
        "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN",
        "ACCESS_KEY",
        "SECRET_KEY",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok())
    .filter(|value| !value.is_empty())
    .collect()
}

fn mint_infrastructure_failure(exit_code: i32) -> Option<MintInfrastructureFailure> {
    if (125..=127).contains(&exit_code) {
        Some(MintInfrastructureFailure::ContainerStart)
    } else if exit_code >= 128 {
        Some(MintInfrastructureFailure::ContainerRuntime)
    } else {
        None
    }
}

fn read_bounded_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{description} {} must be a regular file, not a symlink",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_MINT_CAPTURE_BYTES,
        "{description} {} exceeds the {} byte limit",
        path.display(),
        MAX_MINT_CAPTURE_BYTES
    );
    fs::read(path).with_context(|| format!("read {description} {}", path.display()))
}

fn read_optional_bounded_file(path: &Path, description: &str) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_bounded_file(path, description).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect {description} {}", path.display()))
        }
    }
}

fn print_protocol_suite_json(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("protocol-suite-json requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "protocol-suite-json accepts exactly one path"
    );
    println!("{}", resolve_protocol_suite_yaml(path)?.to_json()?);
    Ok(())
}

async fn print_protocol_suite_plan(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("protocol-suite-plan requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "protocol-suite-plan accepts exactly one path"
    );
    println!("{}", plan_protocol_suite_from_yaml(path).await?.to_json()?);
    Ok(())
}

async fn run_protocol_suite(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("protocol-suite-run requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "protocol-suite-run accepts exactly one path"
    );
    run_protocol_suite_from_yaml(path).await
}

fn print_protocol_suite_template() -> Result<()> {
    print!("{}", protocol_suite_template_yaml());
    Ok(())
}

fn validate_protocol_suite(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("protocol-suite-validate requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "protocol-suite-validate accepts exactly one path"
    );
    let resolved = resolve_protocol_suite_yaml(path)?;
    println!(
        "protocol suite {} is valid: {} case(s)",
        resolved.metadata.name,
        resolved.cases.len()
    );
    Ok(())
}

fn print_fault_console_json(mut args: impl Iterator<Item = String>) -> Result<()> {
    let artifact_root = args
        .next()
        .context("fault-console-json requires artifact root")?;
    ensure!(
        args.next().is_none(),
        "fault-console-json accepts exactly one artifact root"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&build_console_snapshot(artifact_root)?)?
    );
    Ok(())
}

async fn serve_fault_console(mut args: impl Iterator<Item = String>) -> Result<()> {
    let options = parse_fault_console_serve_args(&mut args)?;
    if !options.addr.ip().is_loopback() {
        eprintln!(
            "WARNING: fault-console-serve is binding to non-loopback address {}; artifact contents may be exposed beyond this host",
            options.addr
        );
    }

    serve_console(options.artifact_root, options.addr).await
}

#[derive(Debug, PartialEq, Eq)]
struct FaultConsoleServeOptions {
    artifact_root: String,
    addr: SocketAddr,
}

fn parse_fault_console_serve_args(
    mut args: impl Iterator<Item = String>,
) -> Result<FaultConsoleServeOptions> {
    let artifact_root = args
        .next()
        .context("fault-console-serve requires artifact root")?;
    let mut addr = "127.0.0.1:0"
        .parse::<SocketAddr>()
        .expect("default console address is valid");
    let mut allow_non_loopback = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                let raw_addr = args
                    .next()
                    .context("fault-console-serve --addr requires socket address")?;
                addr = raw_addr
                    .parse()
                    .with_context(|| format!("parse fault-console-serve --addr {raw_addr}"))?;
            }
            "--allow-non-loopback" => allow_non_loopback = true,
            _ => bail!("unknown fault-console-serve option: {arg}"),
        }
    }

    if !addr.ip().is_loopback() && !allow_non_loopback {
        bail!(
            "fault-console-serve refuses non-loopback bind address {addr}; pass --allow-non-loopback to expose the console beyond localhost"
        );
    }

    Ok(FaultConsoleServeOptions {
        artifact_root,
        addr,
    })
}

fn print_fault_catalog_json() -> Result<()> {
    println!("{}", scenario_catalog_json()?);
    Ok(())
}

fn print_fault_qualification_catalog_json() -> Result<()> {
    println!("{}", planned_qualification_catalog_json()?);
    Ok(())
}

fn print_fault_required_artifacts_json() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&FaultRunArtifactSpec::required_names())?
    );
    Ok(())
}

fn print_fault_suite_json(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("fault-suite-json requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "fault-suite-json accepts exactly one path"
    );
    println!("{}", resolve_fault_suite_yaml(path)?.to_json()?);
    Ok(())
}

fn print_fault_suite_plan(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("fault-suite-plan requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "fault-suite-plan accepts exactly one path"
    );
    println!("{}", plan_fault_suite_from_yaml(path)?.to_json()?);
    Ok(())
}

fn print_fault_suite_template() -> Result<()> {
    print!("{}", fault_suite_template_yaml());
    Ok(())
}

async fn run_fault_suite(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("fault-suite-run requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "fault-suite-run accepts exactly one path"
    );
    run_fault_suite_from_yaml(path).await
}

fn validate_fault_suite(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .context("fault-suite-validate requires suite yaml path")?;
    ensure!(
        args.next().is_none(),
        "fault-suite-validate accepts exactly one path"
    );
    let resolved = resolve_fault_suite_yaml(path)?;
    println!(
        "fault suite {} is valid: {} scenario(s)",
        resolved.metadata.name,
        resolved.scenarios.len()
    );
    Ok(())
}

fn analyze_ack_calibration(mut args: impl Iterator<Item = String>) -> Result<()> {
    let strict = args.next().context("requires strict suite root")?;
    let relaxed = args.next().context("requires relaxed suite root")?;
    ensure!(args.next().is_none(), "accepts exactly two suite roots");
    let report = s3chaos::fault::ack_calibration::validate_ack_calibration_pair(
        std::path::Path::new(&strict),
        std::path::Path::new(&relaxed),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn validate_fault_artifacts_command(mut args: impl Iterator<Item = String>) -> Result<()> {
    let scenario = args
        .next()
        .context("fault-validate-artifacts requires scenario")?;
    let artifact_root = args
        .next()
        .context("fault-validate-artifacts requires artifact root")?;
    let mut summary_tsv = false;
    for arg in args {
        match arg.as_str() {
            "--validation-summary-tsv" => summary_tsv = true,
            _ => bail!("unknown fault-validate-artifacts option: {arg}"),
        }
    }
    let options = ArtifactValidationOptions::from_env(scenario, artifact_root)?;
    let report = validate_fault_artifacts_and_write_report(&options)?;
    if summary_tsv {
        println!("{}", report.validation_summary_tsv_row()?);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

fn validate_fault_run_spec_equivalence(mut args: impl Iterator<Item = String>) -> Result<()> {
    let json_path = args
        .next()
        .context("fault-run-spec-equal requires run-spec.json path")?;
    let yaml_path = args
        .next()
        .context("fault-run-spec-equal requires run-spec.yaml path")?;
    ensure!(
        args.next().is_none(),
        "fault-run-spec-equal accepts exactly two paths"
    );

    let json_raw = std::fs::read_to_string(&json_path)
        .with_context(|| format!("read run spec json {json_path}"))?;
    let yaml_raw = std::fs::read_to_string(&yaml_path)
        .with_context(|| format!("read run spec yaml {yaml_path}"))?;
    let json_spec = serde_json::from_str::<FaultRunSpec>(&json_raw)
        .with_context(|| format!("parse run spec json {json_path}"))?;
    let yaml_spec = serde_yaml_ng::from_str::<FaultRunSpec>(&yaml_raw)
        .with_context(|| format!("parse run spec yaml {yaml_path}"))?;

    ensure!(
        json_spec == yaml_spec,
        "run spec JSON and YAML artifacts do not describe the same contract"
    );
    println!("run spec JSON/YAML contract matches");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        mint_infrastructure_failure, parse_fault_console_serve_args,
        validate_verified_mint_target_fingerprint,
    };
    use s3chaos::protocol::mint::MintInfrastructureFailure;
    use std::net::SocketAddr;

    fn args<'a>(items: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
        items.iter().map(|item| item.to_string())
    }

    #[test]
    fn mint_docker_exit_codes_distinguish_start_and_runtime_failures() {
        assert_eq!(mint_infrastructure_failure(1), None);
        assert_eq!(
            mint_infrastructure_failure(125),
            Some(MintInfrastructureFailure::ContainerStart)
        );
        assert_eq!(
            mint_infrastructure_failure(127),
            Some(MintInfrastructureFailure::ContainerStart)
        );
        assert_eq!(
            mint_infrastructure_failure(137),
            Some(MintInfrastructureFailure::ContainerRuntime)
        );
    }

    #[test]
    fn mint_evaluation_requires_the_preflight_fingerprint() {
        let expected = "1111111111111111111111111111111111111111111111111111111111111111";
        validate_verified_mint_target_fingerprint(&format!("sha256:{expected}"), expected)
            .expect("matching verified fingerprint");
        assert!(validate_verified_mint_target_fingerprint("sha256:changed", expected).is_err());
    }

    #[test]
    fn fault_console_serve_defaults_to_loopback_addr() {
        let options = parse_fault_console_serve_args(args(&["artifacts"])).expect("options");

        assert_eq!(options.artifact_root, "artifacts");
        assert_eq!(
            options.addr,
            "127.0.0.1:0".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn fault_console_serve_rejects_non_loopback_addr_without_flag() {
        let error = parse_fault_console_serve_args(args(&["artifacts", "--addr", "0.0.0.0:8080"]))
            .expect_err("non-loopback without flag");

        let message = error.to_string();
        assert!(message.contains("refuses non-loopback bind address"));
        assert!(message.contains("--allow-non-loopback"));
    }

    #[test]
    fn fault_console_serve_allows_non_loopback_addr_with_flag() {
        let options = parse_fault_console_serve_args(args(&[
            "artifacts",
            "--addr",
            "0.0.0.0:8080",
            "--allow-non-loopback",
        ]))
        .expect("non-loopback with flag");

        assert_eq!(
            options.addr,
            "0.0.0.0:8080".parse::<SocketAddr>().expect("addr")
        );
    }
}
