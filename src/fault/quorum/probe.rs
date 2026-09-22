// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! Closed, unprivileged filesystem probes run inside the exact RustFS container.
//! Setup failures are never reported as failures of the requested operation.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const PROBE_ROUNDS: u32 = 3;
pub const PROBE_INTERVAL_MS: u64 = 1000;
pub const PROBE_BINARY: &str = "/usr/local/bin/s3chaos-quorum-probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOperation {
    Read,
    Write,
    Fsync,
    Rename,
    Unlink,
}
impl ProbeOperation {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Fsync,
        Self::Rename,
        Self::Unlink,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Fsync => "fsync",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeFile {
    pub round: u32,
    pub operation: ProbeOperation,
    pub inode: u64,
    pub device: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeFixture {
    pub protocol_version: u8,
    pub helper_sha256: String,
    pub path: String,
    pub nonce: String,
    pub directory_inode: u64,
    pub directory_device: u64,
    pub files: Vec<ProbeFile>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeSample {
    pub round: u32,
    pub operation: ProbeOperation,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub setup_errno: Option<i32>,
    pub operation_errno: Option<i32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeReceipt {
    pub fixture: ProbeFixture,
    pub active_device: u64,
    pub samples: Vec<ProbeSample>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeRequest {
    Stage { path: String, nonce: String },
    Probe { fixture: ProbeFixture },
    Cleanup { fixture: ProbeFixture },
    CleanupPending { path: String, nonce: String },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeResponse {
    Staged { fixture: ProbeFixture },
    Probed { receipt: ProbeReceipt },
    Cleaned { fixture: ProbeFixture },
    CleanedPending { path: String, nonce: String },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn cname(name: &str) -> Result<CString> {
    CString::new(name).context("NUL in probe path")
}
fn filename(round: u32, operation: ProbeOperation) -> String {
    format!("{round}-{}", operation.name())
}
fn open_dir(path: &str) -> Result<File> {
    ensure!(
        path.starts_with('/') && !path.split('/').any(|part| part == ".."),
        "invalid probe path"
    );
    ensure!(
        path.rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(".s3chaos-quorum-")),
        "probe path is not run-owned"
    );
    let path = cname(path)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "open probe directory: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_file(root: &File, name: &str, create: bool) -> std::io::Result<File> {
    let name = CString::new(name).expect("generated filename");
    let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if create {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn unlink(root: &File, name: &str) -> std::io::Result<()> {
    let name = CString::new(name).expect("generated filename");
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
impl ProbeFixture {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == 1
                && self.helper_sha256.len() == 64
                && self.helper_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "unsupported quorum helper protocol or identity"
        );
        ensure!(
            self.nonce.len() == 64 && self.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid probe nonce"
        );
        ensure!(
            self.files.len() == PROBE_ROUNDS as usize * ProbeOperation::ALL.len(),
            "incomplete probe fixture"
        );
        for (index, file) in self.files.iter().enumerate() {
            ensure!(
                file.round == index as u32 / 5 && file.operation == ProbeOperation::ALL[index % 5],
                "unexpected probe fixture operation order"
            );
        }
        Ok(())
    }
    fn open(&self) -> Result<File> {
        self.validate()?;
        let root = open_dir(&self.path)?;
        let metadata = root.metadata()?;
        ensure!(
            metadata.ino() == self.directory_inode && metadata.dev() == self.directory_device,
            "probe directory generation changed"
        );
        let mut marker = open_file(&root, "owner", false)?;
        let mut nonce = String::new();
        marker.read_to_string(&mut nonce)?;
        ensure!(nonce == self.nonce, "probe owner changed");
        Ok(root)
    }
}
impl ProbeReceipt {
    pub fn qualifies(&self) -> bool {
        self.fixture.validate().is_ok()
            && self.active_device != 0
            && self.samples.len() == self.fixture.files.len()
            && self
                .samples
                .iter()
                .zip(&self.fixture.files)
                .all(|(sample, file)| {
                    sample.round == file.round
                        && sample.operation == file.operation
                        && sample.setup_errno.is_none()
                        && sample.operation_errno == Some(libc::EIO)
                        && sample.started_at_ms > 0
                        && sample.completed_at_ms >= sample.started_at_ms
                })
            && self.samples.windows(2).all(|pair| {
                pair[1].started_at_ms >= pair[0].completed_at_ms
                    && (pair[1].round == pair[0].round
                        || pair[1].started_at_ms - pair[0].completed_at_ms >= PROBE_INTERVAL_MS)
            })
    }
}
pub fn execute(request: ProbeRequest) -> Result<ProbeResponse> {
    match request {
        ProbeRequest::Stage { path, nonce } => {
            ensure!(
                nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid nonce"
            );
            // Exclusive creation prevents claiming or deleting an existing directory.
            std::fs::create_dir(&path).context("exclusively create probe directory")?;
            let staged = (|| -> Result<ProbeFixture> {
                let root = open_dir(&path)?;
                let metadata = root.metadata()?;
                let mut marker = open_file(&root, "owner", true)?;
                marker.write_all(nonce.as_bytes())?;
                marker.sync_all()?;
                let mut files = Vec::new();
                for round in 0..PROBE_ROUNDS {
                    for operation in ProbeOperation::ALL {
                        let mut file = open_file(&root, &filename(round, operation), true)?;
                        file.write_all(b"s3chaos-independent-quorum-probe")?;
                        file.sync_all()?;
                        let metadata = file.metadata()?;
                        files.push(ProbeFile {
                            round,
                            operation,
                            inode: metadata.ino(),
                            device: metadata.dev(),
                        });
                    }
                }
                root.sync_all()?;
                Ok(ProbeFixture {
                    protocol_version: 1,
                    helper_sha256: helper_sha256()?,
                    path: path.clone(),
                    nonce,
                    directory_inode: metadata.ino(),
                    directory_device: metadata.dev(),
                    files,
                })
            })();
            match staged {
                Ok(fixture) => Ok(ProbeResponse::Staged { fixture }),
                Err(error) => {
                    if let Ok(root) = open_dir(&path) {
                        for round in 0..PROBE_ROUNDS {
                            for operation in ProbeOperation::ALL {
                                let _ = unlink(&root, &filename(round, operation));
                            }
                        }
                        let _ = unlink(&root, "owner");
                    }
                    let _ = std::fs::remove_dir(path);
                    Err(error)
                }
            }
        }
        ProbeRequest::Probe { fixture } => {
            // The owner file is intentionally not read under fault: READ must fail.
            fixture.validate()?;
            ensure!(
                fixture.helper_sha256 == helper_sha256()?,
                "quorum helper changed after staging"
            );
            let root = open_dir(&fixture.path)?;
            let metadata = root.metadata()?;
            // IOChaos remounts the volume through FUSE. Toda preserves backing
            // inodes, but the kernel assigns a new st_dev to that mount.
            ensure!(
                metadata.ino() == fixture.directory_inode,
                "probe directory generation changed"
            );
            let active_device = metadata.dev();
            let mut samples = Vec::new();
            for target in &fixture.files {
                if target.round > 0 && target.operation == ProbeOperation::Read {
                    std::thread::sleep(Duration::from_millis(PROBE_INTERVAL_MS));
                }
                let started_at_ms = now_ms();
                let setup = open_file(&root, &filename(target.round, target.operation), false)
                    .and_then(|file| {
                        let metadata = file.metadata()?;
                        if metadata.ino() != target.inode || metadata.dev() != active_device {
                            return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
                        }
                        Ok(file)
                    });
                let (setup_errno, operation_errno) = match setup {
                    Err(error) => (Some(error.raw_os_error().unwrap_or(-1)), None),
                    Ok(mut file) => {
                        let result = match target.operation {
                            ProbeOperation::Read => file.read_exact(&mut [0u8; 1]),
                            ProbeOperation::Write => file.write_all(b"probe"),
                            ProbeOperation::Fsync => file.sync_all(),
                            ProbeOperation::Rename => {
                                let source = cname(&filename(target.round, target.operation))?;
                                let destination = cname(&format!("{}-renamed", target.round))?;
                                if unsafe {
                                    libc::renameat(
                                        root.as_raw_fd(),
                                        source.as_ptr(),
                                        root.as_raw_fd(),
                                        destination.as_ptr(),
                                    )
                                } < 0
                                {
                                    Err(std::io::Error::last_os_error())
                                } else {
                                    Ok(())
                                }
                            }
                            ProbeOperation::Unlink => {
                                unlink(&root, &filename(target.round, target.operation))
                            }
                        };
                        (
                            None,
                            result.err().map(|error| error.raw_os_error().unwrap_or(-1)),
                        )
                    }
                };
                samples.push(ProbeSample {
                    round: target.round,
                    operation: target.operation,
                    started_at_ms,
                    completed_at_ms: now_ms(),
                    setup_errno,
                    operation_errno,
                });
            }
            Ok(ProbeResponse::Probed {
                receipt: ProbeReceipt {
                    fixture,
                    active_device,
                    samples,
                },
            })
        }
        ProbeRequest::CleanupPending { path, nonce } => {
            ensure!(
                nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid pending cleanup nonce"
            );
            if std::path::Path::new(&path).try_exists()? {
                let root = open_dir(&path)?;
                let mut owner = String::new();
                open_file(&root, "owner", false)?.read_to_string(&mut owner)?;
                ensure!(
                    owner == nonce,
                    "pending probe directory belongs to another run"
                );
                remove_files(&root)?;
                std::fs::remove_dir(&path)?;
            }
            Ok(ProbeResponse::CleanedPending { path, nonce })
        }
        ProbeRequest::Cleanup { fixture } => {
            let root = fixture.open()?;
            remove_files(&root)?;
            std::fs::remove_dir(&fixture.path)?;
            Ok(ProbeResponse::Cleaned { fixture })
        }
    }
}

fn helper_sha256() -> Result<String> {
    use sha2::{Digest, Sha256};
    static HASH: std::sync::OnceLock<std::result::Result<String, String>> =
        std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        (|| -> Result<String> {
            let mut file = File::open(std::env::current_exe()?)?;
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            Ok(hex::encode(hash.finalize()))
        })()
        .map_err(|error| format!("{error:#}"))
    })
    .as_ref()
    .cloned()
    .map_err(|error| anyhow::anyhow!(error.clone()))
}

#[cfg(test)]
pub(crate) fn test_receipt(path: String, nonce: String, start: u64) -> ProbeReceipt {
    let files = (0..PROBE_ROUNDS)
        .flat_map(|round| {
            ProbeOperation::ALL
                .into_iter()
                .map(move |operation| ProbeFile {
                    round,
                    operation,
                    inode: u64::from(round) * 5 + operation as u64 + 1,
                    device: 1,
                })
        })
        .collect::<Vec<_>>();
    let samples = files
        .iter()
        .map(|file| ProbeSample {
            round: file.round,
            operation: file.operation,
            started_at_ms: start + u64::from(file.round) * PROBE_INTERVAL_MS,
            completed_at_ms: start + u64::from(file.round) * PROBE_INTERVAL_MS,
            setup_errno: None,
            operation_errno: Some(libc::EIO),
        })
        .collect();
    ProbeReceipt {
        active_device: 1,
        fixture: ProbeFixture {
            protocol_version: 1,
            helper_sha256: "a".repeat(64),
            path,
            nonce,
            directory_inode: 1,
            directory_device: 1,
            files,
        },
        samples,
    }
}

fn remove_files(root: &File) -> Result<()> {
    for round in 0..PROBE_ROUNDS {
        for name in ProbeOperation::ALL
            .into_iter()
            .map(|operation| filename(round, operation))
            .chain(std::iter::once(format!("{round}-renamed")))
        {
            if let Err(error) = unlink(root, &name) {
                ensure!(
                    error.kind() == std::io::ErrorKind::NotFound,
                    "remove probe file: {error}"
                );
            }
        }
    }
    unlink(root, "owner")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stage(root: &std::path::Path) -> ProbeFixture {
        match execute(ProbeRequest::Stage {
            path: root
                .join(".s3chaos-quorum-test")
                .to_string_lossy()
                .into_owned(),
            nonce: "a".repeat(64),
        })
        .unwrap()
        {
            ProbeResponse::Staged { fixture } => fixture,
            _ => panic!("stage response"),
        }
    }
    #[test]
    fn independent_syscall_successes_do_not_qualify_and_cleanup_is_contained() {
        let root = tempfile::tempdir().unwrap();
        let fixture = stage(root.path());
        let ProbeResponse::Probed { receipt } = execute(ProbeRequest::Probe {
            fixture: fixture.clone(),
        })
        .unwrap() else {
            panic!("probe response")
        };
        assert!(!receipt.qualifies());
        assert!(
            receipt
                .samples
                .iter()
                .all(|sample| sample.setup_errno.is_none() && sample.operation_errno.is_none())
        );
        execute(ProbeRequest::Cleanup { fixture }).unwrap();
        assert!(root.path().read_dir().unwrap().next().is_none());
    }
    #[test]
    fn absent_source_is_setup_failure_not_rename_eio() {
        let root = tempfile::tempdir().unwrap();
        let fixture = stage(root.path());
        std::fs::remove_file(std::path::Path::new(&fixture.path).join("0-rename")).unwrap();
        let ProbeResponse::Probed { receipt } = execute(ProbeRequest::Probe {
            fixture: fixture.clone(),
        })
        .unwrap() else {
            panic!("probe response")
        };
        let sample = &receipt.samples[3];
        assert_eq!(sample.setup_errno, Some(libc::ENOENT));
        assert_eq!(sample.operation_errno, None);
        assert!(!receipt.qualifies());
        execute(ProbeRequest::Cleanup { fixture }).unwrap();
    }
    #[test]
    fn sustained_complete_receipts_reject_leaks_transport_and_truncation() {
        let receipt = test_receipt(
            "/data/.s3chaos-quorum-test".to_string(),
            "a".repeat(64),
            100,
        );
        assert!(receipt.qualifies());
        for index in 0..receipt.samples.len() {
            let mut leaky = receipt.clone();
            leaky.samples[index].operation_errno = None;
            assert!(!leaky.qualifies());
            let mut setup = receipt.clone();
            setup.samples[index].setup_errno = Some(libc::EIO);
            assert!(!setup.qualifies());
        }
        let mut truncated = receipt.clone();
        truncated.samples.pop();
        assert!(!truncated.qualifies());
        let mut burst = receipt;
        burst.samples[5].started_at_ms = 101;
        assert!(!burst.qualifies());
    }
    #[test]
    fn active_probe_does_not_read_owner_and_lost_stage_receipt_can_be_cleaned() {
        let root = tempfile::tempdir().unwrap();
        let fixture = stage(root.path());
        let owner = std::path::Path::new(&fixture.path).join("owner");
        let saved = root.path().join("saved-owner");
        std::fs::rename(&owner, &saved).unwrap();
        let response = execute(ProbeRequest::Probe {
            fixture: fixture.clone(),
        })
        .unwrap();
        let ProbeResponse::Probed { receipt } = response else {
            panic!("probe response")
        };
        assert_eq!(receipt.samples.len(), 15);
        assert!(
            receipt
                .samples
                .iter()
                .all(|sample| sample.setup_errno.is_none())
        );
        std::fs::rename(&saved, &owner).unwrap();
        execute(ProbeRequest::CleanupPending {
            path: fixture.path.clone(),
            nonce: fixture.nonce.clone(),
        })
        .unwrap();
        assert!(!std::path::Path::new(&fixture.path).exists());
        execute(ProbeRequest::CleanupPending {
            path: fixture.path,
            nonce: fixture.nonce,
        })
        .unwrap();
    }
    #[test]
    fn active_fuse_device_may_differ_but_inode_generation_must_match() {
        let root = tempfile::tempdir().unwrap();
        let fixture = stage(root.path());
        let mut before_remount = fixture.clone();
        before_remount.directory_device ^= 1;
        for file in &mut before_remount.files {
            file.device ^= 1;
        }
        let ProbeResponse::Probed { receipt } = execute(ProbeRequest::Probe {
            fixture: before_remount,
        })
        .unwrap() else {
            panic!("probe response")
        };
        assert_eq!(receipt.active_device, fixture.directory_device);
        assert!(
            receipt
                .samples
                .iter()
                .all(|sample| sample.setup_errno.is_none())
        );
        let mut replaced = fixture.clone();
        replaced.directory_inode += 1;
        assert!(execute(ProbeRequest::Probe { fixture: replaced }).is_err());
        execute(ProbeRequest::Cleanup { fixture }).unwrap();
    }
    #[test]
    fn helper_generation_and_owner_changes_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let fixture = stage(root.path());
        let mut wrong = fixture.clone();
        wrong.helper_sha256 = "0".repeat(64);
        assert!(execute(ProbeRequest::Probe { fixture: wrong }).is_err());
        let mut wrong = fixture.clone();
        wrong.nonce = "b".repeat(64);
        assert!(execute(ProbeRequest::Cleanup { fixture: wrong }).is_err());
        execute(ProbeRequest::Cleanup { fixture }).unwrap();
    }
}
