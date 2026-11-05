// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use std::io;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl ProcessIdentity {
    pub fn current() -> Option<Self> {
        Self::for_pid(std::process::id())
    }

    pub fn for_pid(pid: u32) -> Option<Self> {
        Some(Self {
            pid,
            boot_id: boot_id().ok()?,
            start_ticks: process_start(pid).ok()?,
            namespace: Some(process_namespace().ok()?),
        })
    }

    /// Process absence proves termination only in the recorded host boot and PID namespace.
    pub fn is_running(&self) -> Option<bool> {
        if boot_id().ok()? != self.boot_id
            || self.namespace.as_deref()? != process_namespace().ok()?
        {
            return None;
        }
        match process_start(self.pid) {
            Ok(start) => Some(start == self.start_ticks),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    }
}

#[cfg(target_os = "linux")]
fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}

#[cfg(target_os = "linux")]
fn process_namespace() -> io::Result<String> {
    let self_stat = std::fs::read_to_string("/proc/self/stat")?;
    let visible_pid = self_stat
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok());
    if visible_pid != Some(std::process::id()) {
        return Err(io::Error::other(
            "proc filesystem belongs to another PID namespace",
        ));
    }
    let namespace = std::fs::read_link("/proc/self/ns/pid")?;
    namespace
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| io::Error::other("PID namespace is not UTF-8"))
}

#[cfg(target_os = "linux")]
fn process_start(pid: u32) -> io::Result<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .map(str::to_string)
        .ok_or_else(|| io::Error::other("process start time is missing"))
}

#[cfg(target_os = "linux")]
pub fn parent_pid() -> Option<u32> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> io::Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} could not establish process identity"
        )));
    }
    let value = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::other("empty process identity"));
    }
    Ok(value.into())
}

#[cfg(target_os = "macos")]
fn boot_id() -> io::Result<String> {
    command_output("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])
}

#[cfg(target_os = "macos")]
fn process_namespace() -> io::Result<String> {
    Ok("macos".into())
}

#[cfg(target_os = "macos")]
fn process_start(pid: u32) -> io::Result<String> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?;
    if output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "process is absent"));
    }
    if !output.status.success() {
        return Err(io::Error::other("ps could not establish process identity"));
    }
    let start = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    if start.trim().is_empty() {
        return Err(io::Error::other("process start time is empty"));
    }
    Ok(start.trim().into())
}

#[cfg(target_os = "macos")]
pub fn parent_pid() -> Option<u32> {
    command_output(
        "/bin/ps",
        &["-p", &std::process::id().to_string(), "-o", "ppid="],
    )
    .ok()?
    .parse()
    .ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn boot_id() -> io::Result<String> {
    Err(io::Error::other(
        "process identity is unsupported on this platform",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_namespace() -> io::Result<String> {
    Err(io::Error::other(
        "process identity is unsupported on this platform",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_start(_: u32) -> io::Result<String> {
    Err(io::Error::other(
        "process identity is unsupported on this platform",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn parent_pid() -> Option<u32> {
    None
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn current_process_requires_its_exact_boot_and_namespace() {
        let identity = ProcessIdentity::current().expect("current process identity");
        assert_eq!(identity.is_running(), Some(true));
        let mut changed = identity.clone();
        changed.boot_id.push_str("-different");
        assert_eq!(changed.is_running(), None);
        changed = identity.clone();
        changed.namespace = Some("another-namespace".into());
        assert_eq!(changed.is_running(), None);
        changed = identity;
        changed.namespace = None;
        assert_eq!(changed.is_running(), None);
    }

    #[test]
    fn old_records_cannot_prove_that_a_process_ended() {
        let value = serde_json::json!({"pid":1,"bootId":"old","startTicks":"1"});
        let identity: ProcessIdentity = serde_json::from_value(value).unwrap();
        assert_eq!(identity.is_running(), None);
    }

    #[test]
    fn a_reaped_child_has_confirmed_termination_in_the_same_namespace() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = ProcessIdentity::for_pid(child.id()).expect("child process identity");
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(identity.is_running(), Some(false));
    }
}
