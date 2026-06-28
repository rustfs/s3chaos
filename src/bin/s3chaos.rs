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
use s3chaos::fault::{scenarios::scenario_catalog_json, spec::FaultRunSpec};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "help" | "--help" | "-h" => print_help(),
        "fault-catalog-json" => print_fault_catalog_json(),
        "fault-run-spec-equal" => validate_fault_run_spec_equivalence(args),
        unknown => bail!("unknown s3chaos command: {unknown}; run `s3chaos help`"),
    }
}

fn print_help() -> Result<()> {
    println!("S3Chaos fault-test helper");
    println!();
    println!("Commands:");
    println!("  fault-catalog-json");
    println!("  fault-run-spec-equal <run-spec.json> <run-spec.yaml>");
    Ok(())
}

fn print_fault_catalog_json() -> Result<()> {
    println!("{}", scenario_catalog_json()?);
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
