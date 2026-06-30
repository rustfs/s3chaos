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
use s3chaos::fault::{
    artifact_validation::{ArtifactValidationOptions, validate_fault_artifacts},
    runner::run_selected_scenario_from_env,
    scenarios::scenario_catalog_json,
    spec::{FaultRunArtifactSpec, FaultRunSpec},
    suite::{fault_suite_template_yaml, resolve_fault_suite_yaml},
    suite_runner::{plan_fault_suite_from_yaml, run_fault_suite_from_yaml},
};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "help" | "--help" | "-h" => print_help(),
        "fault-catalog-json" => print_fault_catalog_json(),
        "fault-required-artifacts-json" => print_fault_required_artifacts_json(),
        "fault-run" => run_selected_scenario_from_env().await,
        "fault-suite-json" => print_fault_suite_json(args),
        "fault-suite-plan" => print_fault_suite_plan(args),
        "fault-suite-run" => run_fault_suite(args).await,
        "fault-suite-template" => print_fault_suite_template(),
        "fault-suite-validate" => validate_fault_suite(args),
        "fault-validate-artifacts" => validate_fault_artifacts_command(args),
        "fault-run-spec-equal" => validate_fault_run_spec_equivalence(args),
        unknown => bail!("unknown s3chaos command: {unknown}; run `s3chaos help`"),
    }
}

fn print_help() -> Result<()> {
    println!("S3Chaos fault-test helper");
    println!();
    println!("Commands:");
    println!("  fault-catalog-json");
    println!("  fault-required-artifacts-json");
    println!("  fault-run");
    println!("  fault-suite-json <suite.yaml>");
    println!("  fault-suite-plan <suite.yaml>");
    println!("  fault-suite-run <suite.yaml>");
    println!("  fault-suite-template");
    println!("  fault-suite-validate <suite.yaml>");
    println!("  fault-validate-artifacts <scenario> <artifact-root> [--validation-summary-tsv]");
    println!("  fault-run-spec-equal <run-spec.json> <run-spec.yaml>");
    Ok(())
}

fn print_fault_catalog_json() -> Result<()> {
    println!("{}", scenario_catalog_json()?);
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
    let report = validate_fault_artifacts(&options)?;
    if summary_tsv {
        println!("{}", report.validation_summary_tsv_row());
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
