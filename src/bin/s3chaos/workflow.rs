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
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use s3chaos::{
    protocol::suite::{ProtocolExecutionProfile, ProtocolSuite, ProtocolSuiteSelector},
    workflow::{
        config::{self, Config, CredentialSource, FaultTarget, MintTarget, ProtocolTarget},
        report::{self, RunFilter},
        resources,
        runs::{self},
    },
};

#[path = "workflow_execution.rs"]
mod execution;

#[derive(Parser)]
#[command(
    name = "s3chaos",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("S3CHAOS_BUILD_REVISION"), ")"),
    about = "Run and inspect RustFS fault and S3 compatibility tests",
    after_help = "Use `s3chaos list suites` to browse bundled suites. Legacy worker commands remain available via `s3chaos help workers`."
)]
pub struct Cli {
    /// Target configuration file (default: $XDG_CONFIG_HOME/s3chaos/targets.json)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// State directory containing runs and bundled resources
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Kind {
    Fault,
    Protocol,
    Mint,
}
impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fault => "fault",
            Self::Protocol => "protocol",
            Self::Mint => "mint",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Self::from_str(value, false).map_err(anyhow::Error::msg)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Save a target; credentials are referenced by environment variable name
    Init(Box<InitArgs>),
    /// Run a suite, scenario, or Mint profile against a saved target
    Run(RunArgs),
    /// List recorded runs without loading case artifacts
    Runs {
        #[arg(long)]
        kind: Option<Kind>,
        #[arg(long)]
        result: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a run ID or an absolute run directory
    Report {
        run: String,
        #[arg(long)]
        json: bool,
    },
    /// Repeat the recorded configuration in a new run directory
    Reproduce {
        run: String,
        #[arg(long)]
        case: Option<String>,
        /// A newly prepared ephemeral namespace (required for Mint)
        #[arg(long)]
        namespace: Option<String>,
        /// Acknowledge using a different S3Chaos build from the original run
        #[arg(long)]
        use_current_version: bool,
        /// Acknowledge reproducing with the saved image tag when its digest is unavailable
        #[arg(long)]
        use_current_image: bool,
    },
    /// Recover cleanup using the ownership evidence from this exact run
    Cleanup { run: String },
    /// Check target configuration and prerequisites without injecting faults
    Doctor {
        /// Protocol suite to check (defaults to smoke)
        #[arg(long)]
        suite: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long)]
        kind: Kind,
        #[arg(long)]
        case: Option<String>,
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Validate a suite without contacting the target
    Validate { kind: Kind, suite: String },
    /// Serve run history and evidence in a local browser
    Console {
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:0")]
        addr: SocketAddr,
        #[arg(long)]
        allow_non_loopback: bool,
    },
    /// Browse bundled suites or the scenario and protocol case catalogs
    List {
        #[arg(value_enum)]
        what: ListKind,
        #[arg(long)]
        kind: Option<Kind>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ListKind {
    Suites,
    Cases,
    Qualifications,
}

#[derive(Args)]
struct InitArgs {
    #[arg(long)]
    target: String,
    #[arg(long)]
    kind: Kind,
    #[arg(long)]
    context: Option<String>,
    #[arg(long)]
    storage_class: Option<String>,
    #[arg(long)]
    image: Option<String>,
    #[arg(long)]
    namespace: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    region: String,
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, default_value = "rustfs")]
    container: String,
    #[arg(long, default_value = "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY")]
    access_key_env: String,
    #[arg(long, default_value = "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY")]
    secret_key_env: String,
    #[arg(long)]
    session_token_env: Option<String>,
    /// Confirm that this target is dedicated to destructive testing
    #[arg(long)]
    dedicated: bool,
    /// Replace an existing configuration for this target and test kind
    #[arg(long)]
    replace: bool,
    /// Additional non-secret fault setting, NAME=VALUE (repeatable)
    #[arg(long = "option", value_parser = parse_setting)]
    options: Vec<(String, String)>,
    /// OIDC environment reference, DESTINATION=SOURCE (repeatable)
    #[arg(long = "oidc-env", value_parser = parse_setting)]
    oidc: Vec<(String, String)>,
}

#[derive(Args, Clone)]
struct RunArgs {
    kind: Kind,
    #[arg(long)]
    target: String,
    /// Bundled suite name or YAML file (defaults to smoke)
    #[arg(long, conflicts_with = "qualification")]
    suite: Option<String>,
    #[arg(long, conflicts_with = "qualification")]
    case: Option<String>,
    /// Planned fault qualification case
    #[arg(long)]
    qualification: Option<String>,
    /// Prepared ephemeral namespace for Mint; identity is verified before execution
    #[arg(long)]
    namespace: Option<String>,
    /// Retain the fault fixture for investigation after restoration
    #[arg(long)]
    keep_resources: bool,
    #[arg(skip)]
    use_current_image: bool,
}

fn parse_setting(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value.split_once('=').ok_or("expected NAME=VALUE")?;
    if key.is_empty() || value.is_empty() {
        return Err("NAME and VALUE must be non-empty".into());
    }
    Ok((key.into(), value.into()))
}

pub async fn run() -> Result<()> {
    if std::env::args_os().len() == 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    let cli = Cli::parse();
    let data = cli
        .data_dir
        .map(Ok)
        .unwrap_or_else(config::data_directory)?;
    let configuration = cli.config.map(Ok).unwrap_or_else(config::config_path)?;
    match cli.command {
        Command::Init(args) => init(&configuration, &data, *args).await,
        Command::Run(args) => execution::run(&configuration, &data, args, None).await,
        Command::Reproduce {
            run,
            case,
            namespace,
            use_current_version,
            use_current_image,
        } => {
            execution::reproduce(
                &data,
                &run,
                case,
                namespace,
                use_current_version,
                use_current_image,
            )
            .await
        }
        Command::Cleanup { run } => execution::cleanup(&data, &run).await,
        Command::Doctor {
            suite,
            target,
            kind,
            case,
            namespace,
        } => {
            execution::doctor(
                &configuration,
                &data,
                &target,
                kind,
                case.as_deref(),
                namespace.as_deref(),
                suite.as_deref(),
            )
            .await
        }
        Command::Runs {
            kind,
            result,
            since,
            until,
            offset,
            limit,
            json,
        } => {
            let page = report::list_runs_filtered(
                data.join("runs"),
                &RunFilter {
                    kind: kind.map(|kind| kind.as_str().into()),
                    result,
                    since,
                    until,
                },
                offset,
                limit,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                println!("ID\tKIND\tTARGET\tRESULT\tSTARTED");
                for record in &page.runs {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        record.id, record.kind, record.target, record.result, record.started_at
                    );
                }
                println!("{} of {} runs", page.runs.len(), page.total);
                for warning in page.warnings {
                    eprintln!("warning: {warning}");
                }
            }
            Ok(())
        }
        Command::Report { run, json } => {
            let root = runs::resolve_run(&data, &run)?;
            let report = report::read_run_report(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{}: {}\nartifacts: {}",
                    report.kind, report.result, report.artifact_root
                );
                for (name, value) in [
                    ("summary", report.summary),
                    ("failure", report.failure),
                    ("cleanup", report.cleanup),
                ] {
                    if let Some(value) = value {
                        println!("{name}: {}", serde_json::to_string_pretty(&value)?);
                    }
                }
                for warning in report.warnings {
                    eprintln!("warning: {warning}");
                }
                execution::print_next_steps(&root)?;
            }
            Ok(())
        }
        Command::Validate { kind, suite } => {
            let bundled = resources::materialize(&data)?;
            validate_suite(
                kind,
                &resources::suite_path(&bundled, kind.as_str(), &suite)?,
            )?;
            println!("{} suite is valid", kind.as_str());
            Ok(())
        }
        Command::Console {
            root,
            addr,
            allow_non_loopback,
        } => {
            ensure!(
                addr.ip().is_loopback() || allow_non_loopback,
                "console requires a loopback address; remote binding needs --allow-non-loopback"
            );
            let root = root.unwrap_or_else(|| data.join("runs"));
            runs::private_directory(&root)?;
            super::console_server::serve_console(root, addr).await
        }
        Command::List { what, kind } => list(what, kind),
    }
}

fn list(what: ListKind, kind: Option<Kind>) -> Result<()> {
    match what {
        ListKind::Suites => {
            println!("KIND\tSUITE");
            for (name, _) in resources::FILES {
                if let Some((suite_kind, suite)) = name.split_once("/examples/")
                    && kind.is_none_or(|kind| suite_kind == kind.as_str())
                    && let Some(suite) = suite.strip_suffix(".yaml")
                {
                    println!("{suite_kind}\t{suite}");
                }
            }
        }
        ListKind::Cases => match kind {
            Some(Kind::Protocol) => {
                println!("{}", s3chaos::protocol::catalog::protocol_catalog_json()?)
            }
            Some(Kind::Mint) => bail!(
                "Mint case inventory is bundled at protocol/mint/aws-sdk-php-core-inventory.yaml"
            ),
            _ => println!("{}", s3chaos::fault::scenarios::scenario_catalog_json()?),
        },
        ListKind::Qualifications => println!(
            "{}",
            s3chaos::fault::scenarios::planned_qualification_catalog_json()?
        ),
    }
    Ok(())
}

fn validate_suite(kind: Kind, path: &Path) -> Result<()> {
    match kind {
        Kind::Fault => {
            s3chaos::fault::suite::resolve_fault_suite_yaml(path)?;
        }
        Kind::Protocol => {
            s3chaos::protocol::suite::resolve_protocol_suite_yaml(path)?;
        }
        Kind::Mint => bail!(
            "Mint uses its bundled inventory; use doctor --kind mint --namespace NAME to verify a prepared target"
        ),
    }
    Ok(())
}

fn prompt(value: Option<String>, name: &str) -> Result<String> {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        return Ok(value);
    }
    ensure!(
        io::stdin().is_terminal(),
        "--{name} is required in non-interactive mode"
    );
    print!("{name}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    ensure!(!value.trim().is_empty(), "{name} cannot be empty");
    Ok(value.trim().into())
}

async fn init(path: &Path, data: &Path, args: InitArgs) -> Result<()> {
    config::validate_name(&args.target)?;
    if !io::stdin().is_terminal() {
        let required = match args.kind {
            Kind::Fault => vec![
                ("context", &args.context),
                ("storage-class", &args.storage_class),
                ("image", &args.image),
            ],
            Kind::Protocol => vec![("endpoint", &args.endpoint)],
            Kind::Mint => vec![("context", &args.context), ("service", &args.service)],
        };
        let missing = required
            .into_iter()
            .filter(|(_, value)| value.as_ref().is_none_or(|value| value.trim().is_empty()))
            .map(|(name, _)| format!("--{name}"))
            .collect::<Vec<_>>();
        ensure!(
            missing.is_empty(),
            "missing required options: {}",
            missing.join(", ")
        );
    }
    let mut config = if path.exists() {
        Config::load(path)?
    } else {
        Config::default()
    };
    let target = config.targets.entry(args.target.clone()).or_default();
    let occupied = match args.kind {
        Kind::Fault => target.fault.is_some(),
        Kind::Protocol => target.protocol.is_some(),
        Kind::Mint => target.mint.is_some(),
    };
    ensure!(
        !occupied || args.replace,
        "target {} already has {} settings; pass --replace to update them",
        args.target,
        args.kind.as_str()
    );
    let credentials = CredentialSource {
        access_key_env: args.access_key_env,
        secret_key_env: args.secret_key_env,
        session_token_env: args.session_token_env,
    };
    match args.kind {
        Kind::Fault => {
            let profile = FaultTarget {
                context: prompt(args.context, "context")?,
                storage_class: prompt(args.storage_class, "storage-class")?,
                image: prompt(args.image, "image")?,
                namespace: args.namespace,
                tenant: args.tenant,
                options: args.options.into_iter().collect(),
            };
            profile.environment()?;
            target.fault = Some(profile);
        }
        Kind::Protocol => {
            let endpoint = prompt(args.endpoint, "endpoint")?;
            s3chaos::protocol::suite::resolve_protocol_endpoint(&endpoint)?;
            let mut profile = ProtocolTarget {
                endpoint,
                region: args.region,
                fingerprint: "0".repeat(64),
                credentials,
                oidc: args.oidc.into_iter().collect(),
            };
            let fingerprint = execution::inspect_protocol_target(data, &profile).await?;
            println!(
                "Verified deployment: {}\nEndpoint: {}\nFingerprint: {}",
                fingerprint.deployment_id, fingerprint.endpoint, fingerprint.sha256
            );
            let dedicated = if args.dedicated {
                true
            } else if io::stdin().is_terminal() {
                prompt(None, "confirm dedicated destructive test target (type yes)")? == "yes"
            } else {
                false
            };
            ensure!(
                dedicated,
                "confirm a dedicated test target with --dedicated"
            );
            profile.fingerprint = fingerprint.sha256;
            target.protocol = Some(profile);
        }
        Kind::Mint => {
            ensure!(
                args.dedicated,
                "Mint target namespaces are deleted after testing; confirm their dedicated use with --dedicated"
            );
            ensure!(
                args.port.is_some() || args.endpoint.is_some(),
                "Mint requires --port or --endpoint"
            );
            credentials.environment()?;
            target.mint = Some(MintTarget {
                context: prompt(args.context, "context")?,
                service: prompt(args.service, "service")?,
                port: args.port,
                endpoint: args.endpoint,
                region: args.region,
                container: args.container,
                credentials,
            });
        }
    }
    config.save(path)?;
    println!(
        "Saved {} target {} to {}",
        args.kind.as_str(),
        args.target,
        path.display()
    );
    Ok(())
}

fn protocol_suite(
    path: &Path,
    target: &ProtocolTarget,
    case: Option<&str>,
) -> Result<ProtocolSuite> {
    let mut suite = ProtocolSuite::from_yaml_path(path)?;
    if let Some(case) = case {
        suite.selector = ProtocolSuiteSelector {
            cases: vec![case.into()],
            ..Default::default()
        };
        suite.execution.profile = ProtocolExecutionProfile::Custom;
    }
    let cases = suite
        .resolve()?
        .cases
        .into_iter()
        .map(|case| case.id.as_str().to_owned())
        .collect();
    suite.selector = ProtocolSuiteSelector {
        cases,
        ..Default::default()
    };
    suite.target.endpoint = target.endpoint.clone();
    suite.target.region = target.region.clone();
    Ok(suite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_an_oidc_case_retains_its_suite_provider() {
        let cli = Cli::try_parse_from([
            "s3chaos",
            "run",
            "protocol",
            "--target",
            "lab",
            "--suite",
            "oidc-keycloak",
            "--case",
            "oidc-web-identity-basic",
        ])
        .unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        let root = tempfile::tempdir().unwrap();
        let bundled = resources::materialize(root.path()).unwrap();
        let target = ProtocolTarget {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            fingerprint: "a".repeat(64),
            credentials: Default::default(),
            oidc: Default::default(),
        };
        let suite = protocol_suite(
            &resources::suite_path(&bundled, "protocol", args.suite.as_deref().unwrap()).unwrap(),
            &target,
            args.case.as_deref(),
        )
        .unwrap();
        assert!(suite.target.external_identity.is_some());
        assert_eq!(suite.resolve().unwrap().cases.len(), 1);
        assert_eq!(suite.selector.cases, ["oidc-web-identity-basic"]);
    }
}
