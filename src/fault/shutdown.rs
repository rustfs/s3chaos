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

use anyhow::{Context, Result, bail};
use std::future::Future;
use std::time::Duration;

/// A suite-wide monotonic deadline. Expiration unwinds the operation's guards;
/// callers keep asynchronous cleanup outside this boundary.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RunDeadline {
    at: Option<tokio::time::Instant>,
    seconds: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct SuiteDeadlineExceeded(u64);

impl std::fmt::Display for SuiteDeadlineExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "suite maxDuration budget {}s was reached during execution",
            self.0
        )
    }
}
impl std::error::Error for SuiteDeadlineExceeded {}

impl RunDeadline {
    pub(crate) fn new(seconds: Option<u64>) -> Result<Self> {
        let at = seconds
            .map(|seconds| {
                tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(seconds))
                    .context("suite maxDuration exceeds the monotonic clock range")
            })
            .transpose()?;
        Ok(Self { at, seconds })
    }

    pub(crate) fn check(self) -> Result<()> {
        if self.at.is_some_and(|at| tokio::time::Instant::now() >= at) {
            return Err(SuiteDeadlineExceeded(self.seconds.expect("deadline has budget")).into());
        }
        Ok(())
    }

    /// Caps an internally finalized operation to the remaining suite budget.
    /// Callers must await that operation instead of wrapping it in `run`, so
    /// cancellation cannot leave its durable history record unfinished.
    pub(crate) fn bounded_timeout(self, requested: Duration) -> Result<Duration> {
        self.check()?;
        let Some(at) = self.at else {
            return Ok(requested);
        };
        let remaining = at.saturating_duration_since(tokio::time::Instant::now());
        let remaining_ms = u64::try_from(remaining.as_millis())
            .context("remaining suite maxDuration exceeds the supported millisecond range")?;
        if remaining_ms == 0 {
            return Err(SuiteDeadlineExceeded(self.seconds.expect("deadline has budget")).into());
        }
        Ok(requested.min(Duration::from_millis(remaining_ms)))
    }

    /// The suite deadline instant for an internally finalized operation that
    /// caps each of its own requests; `None` when the suite is unbounded.
    /// Like `bounded_timeout`, callers await the operation instead of wrapping
    /// it in `run`.
    pub(crate) fn instant(self) -> Result<Option<tokio::time::Instant>> {
        self.check()?;
        Ok(self.at)
    }

    pub(crate) async fn run<F, T>(self, operation: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.check()?;
        let result = match self.at {
            Some(at) => tokio::time::timeout_at(at, operation)
                .await
                .map_err(|_| SuiteDeadlineExceeded(self.seconds.expect("deadline has budget")))?,
            None => operation.await,
        };
        // A synchronous operation can finish in a single late poll. Never turn
        // that late completion into success simply because it beat the timer.
        self.check()?;
        result
    }
}

pub async fn run_signal_aware<F>(operation: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    run_until_shutdown(operation, shutdown_signal()?).await
}

async fn run_until_shutdown<F, S>(operation: F, shutdown: S) -> Result<()>
where
    F: Future<Output = Result<()>>,
    S: Future<Output = Result<&'static str>>,
{
    let mut operation = Box::pin(operation);
    let mut shutdown = Box::pin(shutdown);
    let signal = tokio::select! {
        result = &mut operation => return result,
        signal = &mut shutdown => signal?,
    };

    // Cancellation drops the complete fault-run future before returning to the
    // shell wrapper, synchronously running storage/Chaos guards and rollback.
    drop(operation);
    bail!("fault execution interrupted by {signal} after graceful unwind")
}

#[cfg(unix)]
fn shutdown_signal() -> Result<impl Future<Output = Result<&'static str>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("listen for SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
    let mut hangup = signal(SignalKind::hangup()).context("listen for SIGHUP")?;
    Ok(async move {
        tokio::select! {
            signal = interrupt.recv() => {
                signal.context("SIGINT listener closed")?;
                Ok("SIGINT")
            }
            signal = terminate.recv() => {
                signal.context("SIGTERM listener closed")?;
                Ok("SIGTERM")
            }
            signal = hangup.recv() => {
                signal.context("SIGHUP listener closed")?;
                Ok("SIGHUP")
            }
        }
    })
}

#[cfg(not(unix))]
fn shutdown_signal() -> Result<impl Future<Output = Result<&'static str>>> {
    Ok(async {
        tokio::signal::ctrl_c()
            .await
            .context("listen for shutdown signal")?;
        Ok("shutdown signal")
    })
}

#[cfg(test)]
mod tests {
    use super::{RunDeadline, SuiteDeadlineExceeded, run_until_shutdown};
    use anyhow::Result;
    use std::{
        future::{pending, ready},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    struct RestoreProbe(Arc<AtomicBool>);

    impl Drop for RestoreProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_drops_fault_future_before_returning() {
        let restored = Arc::new(AtomicBool::new(false));
        let operation = {
            let restored = Arc::clone(&restored);
            async move {
                let _guard = RestoreProbe(restored);
                pending::<()>().await;
                Ok(())
            }
        };

        let shutdown = async {
            tokio::task::yield_now().await;
            Ok("SIGTERM")
        };
        let error = run_until_shutdown(operation, shutdown)
            .await
            .expect_err("shutdown must interrupt the operation");

        assert!(error.to_string().contains("SIGTERM"));
        assert!(restored.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn operation_result_wins_without_waiting_for_shutdown() -> Result<()> {
        run_until_shutdown(ready(Ok(())), pending()).await
    }
    #[tokio::test(start_paused = true)]
    async fn deadline_drops_active_guard_before_cleanup_and_reports_timeout() {
        let restored = Arc::new(AtomicBool::new(false));
        let deadline = RunDeadline::new(Some(3)).expect("deadline");
        let operation = {
            let restored = restored.clone();
            async move {
                let _guard = RestoreProbe(restored);
                pending::<()>().await;
                Ok(())
            }
        };
        let error = deadline.run(operation).await.expect_err("timeout");
        assert!(error.is::<SuiteDeadlineExceeded>());
        assert!(
            restored.load(Ordering::SeqCst),
            "backend restoration precedes outer cleanup"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_shared_across_phases_and_rejects_last_phase_overrun() {
        let deadline = RunDeadline::new(Some(3)).expect("deadline");
        deadline
            .run(async {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                Ok(())
            })
            .await
            .expect("first phase");
        let error = deadline
            .run(async {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                Ok(())
            })
            .await
            .expect_err("last phase cannot get a fresh budget");
        assert!(error.is::<SuiteDeadlineExceeded>());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_deadline_never_starts_more_work() {
        let deadline = RunDeadline::new(Some(1)).expect("deadline");
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let polled = AtomicBool::new(false);
        deadline
            .run(async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("expired");
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn instant_exposes_the_suite_deadline_only_while_budget_remains() {
        assert!(
            RunDeadline::default()
                .instant()
                .expect("unbounded suite")
                .is_none()
        );
        let deadline = RunDeadline::new(Some(2)).expect("deadline");
        let at = deadline
            .instant()
            .expect("budget remains")
            .expect("bounded suite has an instant");
        assert_eq!(
            at.saturating_duration_since(tokio::time::Instant::now()),
            std::time::Duration::from_secs(2)
        );
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        let error = deadline.instant().expect_err("exhausted suite");
        assert!(error.is::<SuiteDeadlineExceeded>());
    }

    #[tokio::test(start_paused = true)]
    async fn internal_timeout_is_capped_to_remaining_suite_budget() {
        let deadline = RunDeadline::new(Some(3)).expect("deadline");
        tokio::time::advance(std::time::Duration::from_secs(2)).await;

        assert_eq!(
            deadline
                .bounded_timeout(std::time::Duration::from_secs(30))
                .expect("remaining budget"),
            std::time::Duration::from_secs(1)
        );
        assert_eq!(
            deadline
                .bounded_timeout(std::time::Duration::from_millis(500))
                .expect("shorter configured timeout"),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            RunDeadline::default()
                .bounded_timeout(std::time::Duration::from_secs(30))
                .expect("unbounded suite"),
            std::time::Duration::from_secs(30)
        );

        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let error = deadline
            .bounded_timeout(std::time::Duration::from_secs(30))
            .expect_err("expired suite");
        assert!(error.is::<SuiteDeadlineExceeded>());
    }
}
