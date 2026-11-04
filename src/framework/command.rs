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

use anyhow::{Context, Result, anyhow, bail, ensure};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<String>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            stdin: None,
            timeout: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn stdin(mut self, stdin: impl Into<String>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn display(&self) -> String {
        let args = self.args.join(" ");
        if args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, args)
        }
    }

    pub fn run(&self) -> Result<CommandOutput> {
        if let Some(timeout) = self.timeout {
            // Synchronous adapters also run inside Tokio tasks. A separate
            // thread keeps the bounded I/O runtime independent of that executor.
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?
                            .block_on(self.run_bounded(timeout))
                    })
                    .join()
                    .map_err(|_| anyhow!("bounded command worker panicked: {}", self.display()))?
            });
        }
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        if self.stdin.is_some() {
            command.stdin(Stdio::piped());
        }

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start command: {}", self.display()))?;

        if let Some(stdin) = &self.stdin {
            child
                .stdin
                .as_mut()
                .context("failed to open command stdin")?
                .write_all(stdin.as_bytes())
                .with_context(|| {
                    format!("failed to write stdin for command: {}", self.display())
                })?;
        }

        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for command: {}", self.display()))?;

        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Run to completion under a hard wall-clock bound without blocking the
    /// async executor. The child is killed when the bound expires or the
    /// future is dropped, so a peer that accepts the connection but never
    /// answers cannot pin the calling task forever.
    pub async fn run_bounded(&self, timeout: Duration) -> Result<CommandOutput> {
        let timeout = self.timeout.map_or(timeout, |limit| limit.min(timeout));
        ensure!(
            !timeout.is_zero(),
            "command deadline elapsed before start: {}",
            self.display()
        );
        let deadline = tokio::time::Instant::now() + timeout;
        let mut command = tokio::process::Command::new(&self.program);
        command.args(&self.args).kill_on_drop(true);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        command
            .stdin(if self.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start command: {}", self.display()))?;
        let input = child.stdin.take();
        let mut stdout = child.stdout.take().context("command stdout is missing")?;
        let mut stderr = child.stderr.take().context("command stderr is missing")?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exchange = async {
            let write = async {
                if let Some(mut input) = input {
                    input
                        .write_all(self.stdin.as_deref().unwrap_or_default().as_bytes())
                        .await?;
                    input.shutdown().await?;
                }
                std::io::Result::Ok(())
            };
            let (status, _, _, _) = tokio::try_join!(
                child.wait(),
                write,
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err)
            )?;
            std::io::Result::Ok(status)
        };
        let result = tokio::time::timeout_at(deadline, exchange).await;
        let status = match result {
            Ok(Ok(status)) => status,
            failure => {
                // Reap before a synchronous caller shuts down its I/O runtime.
                if child.try_wait()?.is_none() {
                    child.kill().await.context("terminate failed command")?;
                }
                return match failure {
                    Ok(Err(error)) => Err(error)
                        .with_context(|| format!("command I/O failed: {}", self.display())),
                    Err(_) => Err(anyhow!(
                        "command timed out after {}s: {}",
                        timeout.as_secs_f64(),
                        self.display()
                    )),
                    Ok(Ok(_)) => unreachable!(),
                };
            }
        };
        Ok(CommandOutput {
            code: status.code(),
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        })
    }

    /// Like `spawn_background_with_log` but with stderr in its own file, for
    /// commands whose stdout is a machine-readable stream.
    pub fn spawn_background_with_logs(
        &self,
        stdout_path: impl AsRef<Path>,
        stderr_path: impl AsRef<Path>,
    ) -> Result<Child> {
        if self.stdin.is_some() {
            bail!(
                "background command stdin is not supported: {}",
                self.display()
            );
        }
        let open = |path: &Path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("open command log {}", path.display()))
        };
        let stdout = open(stdout_path.as_ref())?;
        let stderr = open(stderr_path.as_ref())?;
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start background command: {}", self.display()))
    }

    pub fn spawn_background_with_log(&self, log_path: impl AsRef<Path>) -> Result<Child> {
        if self.stdin.is_some() {
            bail!(
                "background command stdin is not supported: {}",
                self.display()
            );
        }

        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path.as_ref())
            .with_context(|| format!("open command log {}", log_path.as_ref().display()))?;
        let stderr = log
            .try_clone()
            .with_context(|| format!("clone command log {}", log_path.as_ref().display()))?;

        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }

        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start background command: {}", self.display()))
    }

    pub fn run_checked(&self) -> Result<CommandOutput> {
        let output = self.run()?;
        if output.code == Some(0) {
            Ok(output)
        } else {
            bail!(
                "command failed: {}\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
                self.display(),
                output.code,
                output.stdout,
                output.stderr
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CommandSpec;

    #[test]
    fn command_display_keeps_program_and_args_visible() {
        let command = CommandSpec::new("kubectl").args(["get", "pods", "-A"]);

        assert_eq!(command.display(), "kubectl get pods -A");
    }

    #[tokio::test]
    async fn run_bounded_kills_a_hung_command_at_the_bound() {
        let started = std::time::Instant::now();
        let error = CommandSpec::new("sleep")
            .arg("30")
            .run_bounded(std::time::Duration::from_millis(200))
            .await
            .expect_err("a hung command must not outlive its bound");

        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the bound must cut the wait short"
        );
    }

    #[tokio::test]
    async fn run_bounded_treats_output_followed_by_a_hang_as_a_timeout() {
        // Partial output must never be reported as a completed probe.
        let error = CommandSpec::new("sh")
            .args(["-c", "printf ready; sleep 30"])
            .run_bounded(std::time::Duration::from_millis(200))
            .await
            .expect_err("a command that hangs after printing has not finished");

        assert!(error.to_string().contains("timed out"), "{error:#}");
    }

    #[tokio::test]
    async fn run_bounded_returns_output_of_a_finished_command() {
        let output = CommandSpec::new("sh")
            .args(["-c", "printf out; printf err >&2; exit 3"])
            .run_bounded(std::time::Duration::from_secs(10))
            .await
            .expect("command completes");

        assert_eq!(output.code, Some(3));
        assert_eq!(output.stdout, "out");
        assert_eq!(output.stderr, "err");
    }

    #[tokio::test]
    async fn synchronous_timeout_is_enforced_inside_an_async_executor() {
        let started = std::time::Instant::now();
        let error = CommandSpec::new("sleep")
            .arg("30")
            .timeout(std::time::Duration::from_millis(100))
            .run_checked()
            .expect_err("timeout");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[tokio::test]
    async fn bounded_timeout_includes_a_blocked_stdin_writer() {
        let started = std::time::Instant::now();
        let error = CommandSpec::new("sleep")
            .arg("30")
            .stdin("x".repeat(2 * 1024 * 1024))
            .run_bounded(std::time::Duration::from_millis(100))
            .await
            .expect_err("timeout");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[tokio::test]
    async fn bounded_exchange_drains_output_while_sending_input() {
        let payload = "x".repeat(2 * 1024 * 1024);
        let output = CommandSpec::new("cat")
            .stdin(payload.clone())
            .run_bounded(std::time::Duration::from_secs(10))
            .await
            .expect("duplex exchange");
        assert_eq!(output.stdout, payload);
        assert_eq!(output.code, Some(0));
    }

    #[test]
    fn command_display_does_not_include_stdin_payload() {
        let command = CommandSpec::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin("secret: value");

        assert_eq!(command.display(), "kubectl apply -f -");
    }

    #[tokio::test]
    async fn expired_deadline_does_not_start_the_command() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let marker = temporary.path().join("started");
        CommandSpec::new("touch")
            .arg(marker.to_string_lossy())
            .run_bounded(std::time::Duration::ZERO)
            .await
            .expect_err("expired budget");
        assert!(!marker.exists());
    }
}
