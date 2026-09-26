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

//! Privileged storage helper implementation.
//!
//! The helper has two fixed mount roots and one typed JSON protocol. It never
//! accepts a command or argv. Every target below the volume root is opened with
//! `openat2` containment, and the exclusive flock remains held for the entire
//! helper process operation.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, prelude::FileExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::fault::{
    fresh_volume::{FreshVolumeHostProbeRequest, run_fresh_volume_host_probe},
    storage_recovery::{FragmentReferenceState, RustfsShardInventoryResponse, ShardInventoryEntry},
    storage_recovery_lease::StorageRecoveryCleanupProof,
    storage_recovery_runtime::{
        DeviceMapperCommandReceipt, HostGenerationIdentity, OwnedStorageContext,
        STORAGE_RECOVERY_HOST_LOCK_DIRECTORY, StaleDeviceMapperAction, StaleDeviceMapperPlan,
        StaleDeviceMapperTransitionResponse, StorageHelperInvocation, StorageRecoveryHostOperation,
        StorageRecoveryOperationReceipt, context_sha256, host_generation_sha256,
        same_storage_volume_generation,
    },
    xl2_inspector::{
        Xl2InventoryVersionKind, inspect_all_xl_meta, inspect_xl_meta, validate_format_json_drive,
    },
};

pub const STORAGE_HELPER_VOLUME_ROOT: &str = "/target";
pub const STORAGE_HELPER_JOURNAL_ROOT: &str = "/journal";
const FORMAT_JSON_PATH: &str = ".rustfs.sys/format.json";
const MAX_FORMAT_JSON_BYTES: usize = 1024 * 1024;
const MAX_XL_META_BYTES: usize = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
pub const CONTROLLED_SHARD_XOR_MASK: u8 = 0xff;
const MAX_STALE_INVENTORY_OBJECTS: usize = 512;
const MAX_STALE_INVENTORY_ENTRIES: usize = 4_096;
const MAX_STALE_INVENTORY_DEPTH: usize = 32;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const STORAGE_RESOLVE_FLAGS: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;

#[derive(Debug, Clone)]
pub struct StorageHelperRoots {
    pub volume: PathBuf,
    pub journal: PathBuf,
    pub lock: PathBuf,
    pub host_proc: PathBuf,
    pub host_dev: PathBuf,
    #[cfg(test)]
    pub trust_context_host_generation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaleOfflineExpectedVersion {
    pub operation_id: String,
    pub object_key: String,
    pub version_id: String,
    pub object_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaleOwnedOrphanReceipt {
    pub run_id: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub relative_part_path: String,
    pub drive_uuid: String,
    pub fragment_id: String,
    pub object_sha256: String,
    pub fragment_sha256: String,
    pub part_device_id: String,
    pub part_inode: u64,
    pub part_size_bytes: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StaleOfflineHelperOperation {
    InjectOrphan {
        object_key: String,
        version_id: String,
    },
    Inventory {
        snapshot_id: String,
        expected_versions: Vec<StaleOfflineExpectedVersion>,
        orphan: StaleOwnedOrphanReceipt,
        include_orphan: bool,
    },
    RemoveOwnedOrphan {
        orphan: StaleOwnedOrphanReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaleOfflineHelperRequest {
    pub run_id: String,
    pub scenario: String,
    pub volume_root: String,
    pub deployment_id: String,
    pub drive_uuid: String,
    pub filesystem_uuid: String,
    pub bucket: String,
    pub operation: StaleOfflineHelperOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StaleOfflineHelperResponse {
    OrphanInjected {
        receipt: StaleOwnedOrphanReceipt,
    },
    Inventory {
        response: RustfsShardInventoryResponse,
        expected_operation_ids: Vec<String>,
    },
    OrphanRemoved {
        fragment_id: String,
        removed_at_ms: u64,
    },
}

pub fn execute_stale_offline_helper(
    request: StaleOfflineHelperRequest,
) -> Result<StaleOfflineHelperResponse> {
    validate_stale_helper_request(&request, false)?;
    let root = open_directory(Path::new(&request.volume_root), "stale offline volume root")?;
    execute_stale_offline_helper_at_root(&request, &root)
}

fn validate_stale_helper_request(
    request: &StaleOfflineHelperRequest,
    persistent_session: bool,
) -> Result<()> {
    ensure!(
        request.scenario == "stale-disk-return-detect"
            && !request.run_id.trim().is_empty()
            && !request.bucket.trim().is_empty()
            && if persistent_session {
                request.volume_root == STORAGE_HELPER_VOLUME_ROOT
            } else {
                request.volume_root.starts_with("/host/")
            }
            && !request.volume_root.contains("/../")
            && !request.volume_root.ends_with("/.."),
        "stale offline helper request has an invalid run scope or volume root"
    );
    Uuid::parse_str(&request.deployment_id)
        .context("stale offline helper deployment id is not a UUID")?;
    Uuid::parse_str(&request.drive_uuid).context("stale offline helper drive id is not a UUID")?;
    ensure!(
        !request.filesystem_uuid.trim().is_empty(),
        "stale offline helper filesystem id is empty"
    );
    Ok(())
}

fn execute_stale_offline_helper_at_root(
    request: &StaleOfflineHelperRequest,
    root: &File,
) -> Result<StaleOfflineHelperResponse> {
    let format_file = open_beneath(root, FORMAT_JSON_PATH, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    let format = read_limited(&format_file, MAX_FORMAT_JSON_BYTES, "format.json")?;
    validate_format_json_drive(&format, &request.deployment_id, &request.drive_uuid)?;
    match &request.operation {
        StaleOfflineHelperOperation::InjectOrphan {
            object_key,
            version_id,
        } => inject_stale_orphan(request, root, object_key, version_id),
        StaleOfflineHelperOperation::Inventory {
            snapshot_id,
            expected_versions,
            orphan,
            include_orphan,
        } => inventory_stale_scope(
            request,
            root,
            snapshot_id,
            expected_versions,
            orphan,
            *include_orphan,
        ),
        StaleOfflineHelperOperation::RemoveOwnedOrphan { orphan } => {
            remove_stale_orphan(request, root, orphan)
        }
    }
}

fn validate_stale_object_key(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty()
            && !key.starts_with('/')
            && !key.ends_with('/')
            && key
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "stale offline helper object key is not a normalized relative path"
    );
    Ok(())
}

fn open_stale_object_dir(root: &File, bucket: &str, key: &str) -> Result<File> {
    validate_stale_object_key(key)?;
    open_beneath(
        root,
        &format!("{bucket}/{key}"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .context("open stale offline object directory")
}

fn stale_fragment_id(drive_uuid: &str, relative_path: &str, inode: u64) -> String {
    let digest = sha256_bytes(format!("{drive_uuid}\0{relative_path}\0{inode}").as_bytes());
    format!("offline-{digest}")
}

fn inject_stale_orphan(
    request: &StaleOfflineHelperRequest,
    root: &File,
    object_key: &str,
    version_id: &str,
) -> Result<StaleOfflineHelperResponse> {
    validate_stale_object_key(object_key)?;
    let version = Uuid::parse_str(version_id).context("stale orphan id is not a UUID")?;
    ensure!(!version.is_nil(), "stale orphan id is nil");
    let object = open_stale_object_dir(root, &request.bucket, object_key)?;
    open_beneath(&object, "xl.meta", libc::O_RDONLY | libc::O_CLOEXEC, 0)
        .context("stale orphan target object lacks xl.meta")?;
    let directory_name = version.to_string();
    let directory_c = CString::new(directory_name.as_str())?;
    let created = unsafe { libc::mkdirat(object.as_raw_fd(), directory_c.as_ptr(), 0o700) };
    if created != 0 {
        return Err(std::io::Error::last_os_error())
            .context("create run-owned stale orphan directory with exclusive identity");
    }
    let orphan = open_beneath(
        &object,
        &directory_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let payload = format!("s3chaos-stale-orphan:{}:{version_id}", request.run_id).into_bytes();
    let result = (|| -> Result<StaleOwnedOrphanReceipt> {
        let mut part = open_beneath(
            &orphan,
            "part.1",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )?;
        part.write_all(&payload)?;
        part.sync_all().context("fsync stale orphan part")?;
        let metadata = part.metadata().context("stat stale orphan part")?;
        orphan.sync_all().context("fsync stale orphan directory")?;
        object
            .sync_all()
            .context("fsync stale orphan object directory")?;
        root.sync_all().context("fsync stale orphan volume root")?;
        let relative_part_path = format!(
            "{}/{}/{}/part.1",
            request.bucket, object_key, directory_name
        );
        let fragment_sha256 = sha256_bytes(&payload);
        Ok(StaleOwnedOrphanReceipt {
            run_id: request.run_id.clone(),
            bucket: request.bucket.clone(),
            object_key: object_key.to_string(),
            version_id: directory_name,
            relative_part_path: relative_part_path.clone(),
            drive_uuid: request.drive_uuid.clone(),
            fragment_id: stale_fragment_id(
                &request.drive_uuid,
                &relative_part_path,
                metadata.ino(),
            ),
            object_sha256: fragment_sha256.clone(),
            fragment_sha256,
            part_device_id: device_id(&metadata),
            part_inode: metadata.ino(),
            part_size_bytes: metadata.len(),
            created_at_ms: now_ms()?,
        })
    })();
    if result.is_err() {
        let part_c = CString::new("part.1")?;
        let _ = unsafe { libc::unlinkat(orphan.as_raw_fd(), part_c.as_ptr(), 0) };
        let _ =
            unsafe { libc::unlinkat(object.as_raw_fd(), directory_c.as_ptr(), libc::AT_REMOVEDIR) };
        let _ = object.sync_all();
    }
    Ok(StaleOfflineHelperResponse::OrphanInjected { receipt: result? })
}

fn inventory_stale_scope(
    request: &StaleOfflineHelperRequest,
    root: &File,
    snapshot_id: &str,
    expected_versions: &[StaleOfflineExpectedVersion],
    orphan: &StaleOwnedOrphanReceipt,
    include_orphan: bool,
) -> Result<StaleOfflineHelperResponse> {
    Uuid::parse_str(snapshot_id).context("stale inventory snapshot id is not a UUID")?;
    ensure!(
        !expected_versions.is_empty()
            && expected_versions.len() <= MAX_STALE_INVENTORY_OBJECTS
            && orphan.run_id == request.run_id
            && orphan.bucket == request.bucket
            && orphan.drive_uuid == request.drive_uuid,
        "stale inventory scope or orphan receipt is invalid"
    );
    ensure!(
        !request.bucket.is_empty()
            && !request.bucket.contains('/')
            && request.bucket != "."
            && request.bucket != "..",
        "stale inventory bucket is not a normalized path component"
    );
    let mut expected_by_version = BTreeMap::new();
    let mut operation_ids = Vec::with_capacity(expected_versions.len());
    for expected in expected_versions {
        validate_stale_object_key(&expected.object_key)?;
        Uuid::parse_str(&expected.version_id)
            .context("stale inventory expected version id is not a UUID")?;
        ensure!(
            !expected.operation_id.trim().is_empty()
                && expected.object_sha256.len() == 64
                && expected
                    .object_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "stale inventory expected version identity is invalid"
        );
        ensure!(
            expected_by_version
                .insert(
                    (expected.object_key.clone(), expected.version_id.clone()),
                    expected.object_sha256.to_ascii_lowercase(),
                )
                .is_none(),
            "stale inventory contains a duplicate expected object version"
        );
        operation_ids.push(expected.operation_id.clone());
    }
    let scan_started_at_ms = now_ms()?;
    let first = scan_stale_bucket(request, root, &expected_by_version, orphan)?;
    let entries = scan_stale_bucket(request, root, &expected_by_version, orphan)?;
    ensure!(
        first == entries,
        "stale inventory changed between two exhaustive filesystem traversals"
    );
    let injected = entries
        .iter()
        .find(|entry| entry.fragment_id == orphan.fragment_id);
    if include_orphan {
        let injected = injected.context("run-owned stale orphan is absent from inventory")?;
        ensure!(
            injected.object_key == orphan.object_key
                && injected.version_id == orphan.version_id
                && injected.object_sha256 == orphan.object_sha256
                && injected.sha256 == orphan.fragment_sha256
                && injected.reference_state == FragmentReferenceState::OrphanedUncommitted,
            "run-owned stale orphan identity changed before inventory"
        );
    } else {
        ensure!(
            injected.is_none(),
            "run-owned stale orphan remains present after cleanup"
        );
        ensure_absent_beneath(root, &orphan.relative_part_path)?;
    }
    let scan_completed_at_ms = now_ms()?.max(scan_started_at_ms + 1);
    let response = RustfsShardInventoryResponse {
        bucket: request.bucket.clone(),
        drive_uuid: request.drive_uuid.clone(),
        filesystem_uuid: request.filesystem_uuid.clone(),
        snapshot_id: snapshot_id.to_string(),
        scan_started_at_ms,
        scan_completed_at_ms,
        start_cursor: None,
        end_cursor: sha256_bytes(serde_json::to_vec(&entries)?.as_slice()),
        exhausted: true,
        total_count: entries.len(),
        entries,
    };
    Ok(StaleOfflineHelperResponse::Inventory {
        response,
        expected_operation_ids: operation_ids,
    })
}

fn scan_stale_bucket(
    request: &StaleOfflineHelperRequest,
    root: &File,
    expected: &BTreeMap<(String, String), String>,
    orphan: &StaleOwnedOrphanReceipt,
) -> Result<Vec<ShardInventoryEntry>> {
    let bucket = open_beneath(
        root,
        &request.bucket,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .context("open run-owned stale inventory bucket")?;
    let scope_prefix = format!("fault-test/{}", request.run_id);
    validate_stale_object_key(&scope_prefix)?;
    let scope = open_beneath(
        &bucket,
        &scope_prefix,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .context("open run-owned stale inventory prefix")?;
    let mut object_keys = Vec::new();
    discover_stale_objects(&scope, "", 0, &mut object_keys)?;
    ensure!(
        !object_keys.is_empty() && object_keys.len() <= MAX_STALE_INVENTORY_OBJECTS,
        "stale inventory object count is empty or exceeds its bound"
    );

    let mut entries = Vec::new();
    let mut discovered_versions = BTreeSet::new();
    for relative_object_key in object_keys {
        let object_key = format!("{scope_prefix}/{relative_object_key}");
        let object = open_beneath(
            &bucket,
            &object_key,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let xl_meta_file = open_beneath(&object, "xl.meta", libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
        let xl_meta_inode = xl_meta_file
            .metadata()
            .context("stat stale inventory xl.meta")?
            .ino();
        let xl_meta = read_limited(&xl_meta_file, MAX_XL_META_BYTES, "stale inventory xl.meta")?;
        let layouts = inspect_all_xl_meta(&xl_meta)?;
        let mut declared = BTreeMap::new();
        for inventory_layout in layouts {
            discovered_versions.insert((object_key.clone(), inventory_layout.version_id.clone()));
            let expected_hash = expected
                .get(&(object_key.clone(), inventory_layout.version_id.clone()))
                .cloned();
            if let Some(layout) = inventory_layout.shard_layout {
                for relative in layout.relative_part_paths {
                    ensure!(
                        declared
                            .insert(relative, (layout.version_id.clone(), expected_hash.clone()))
                            .is_none(),
                        "XL2 layouts declare the same shard path more than once"
                    );
                }
            } else if inventory_layout.kind == Xl2InventoryVersionKind::Inline {
                let full_relative = format!(
                    "{}/{object_key}/xl.meta#{}",
                    request.bucket, inventory_layout.version_id
                );
                entries.push(ShardInventoryEntry {
                    fragment_id: stale_fragment_id(
                        &request.drive_uuid,
                        &full_relative,
                        xl_meta_inode,
                    ),
                    bucket: request.bucket.clone(),
                    object_key: object_key.clone(),
                    version_id: inventory_layout.version_id,
                    drive_uuid: request.drive_uuid.clone(),
                    object_sha256: expected_hash
                        .clone()
                        .unwrap_or_else(|| sha256_bytes(&xl_meta)),
                    sha256: sha256_bytes(&xl_meta),
                    reference_state: if expected_hash.is_some() {
                        FragmentReferenceState::ReferencedVersion
                    } else {
                        FragmentReferenceState::Unclassified
                    },
                });
            }
        }
        scan_stale_object_parts(
            request,
            &object,
            &object_key,
            &xl_meta,
            &declared,
            orphan,
            &mut entries,
        )?;
    }
    ensure!(
        expected
            .keys()
            .all(|identity| discovered_versions.contains(identity)),
        "an expected S3 object version is absent from the exhaustive XL2 traversal"
    );
    ensure!(
        entries.len() <= MAX_STALE_INVENTORY_ENTRIES,
        "stale inventory entry count exceeds its bound"
    );
    entries.sort();
    Ok(entries)
}

fn discover_stale_objects(
    directory: &File,
    relative: &str,
    depth: usize,
    objects: &mut Vec<String>,
) -> Result<()> {
    ensure!(
        depth <= MAX_STALE_INVENTORY_DEPTH,
        "stale inventory directory depth exceeds its bound"
    );
    let children = contained_directory_entries(directory)?;
    if children
        .iter()
        .any(|(name, is_dir)| name == "xl.meta" && !is_dir)
    {
        ensure!(
            !relative.is_empty(),
            "stale inventory found xl.meta at bucket root"
        );
        objects.push(relative.to_string());
        return Ok(());
    }
    for (name, is_dir) in children {
        ensure!(
            is_dir,
            "stale bucket contains a file outside an XL2 object directory"
        );
        let child = open_beneath(
            directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let child_relative = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        discover_stale_objects(&child, &child_relative, depth + 1, objects)?;
        ensure!(
            objects.len() <= MAX_STALE_INVENTORY_OBJECTS,
            "stale inventory object count exceeds its bound"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_stale_object_parts(
    request: &StaleOfflineHelperRequest,
    object: &File,
    object_key: &str,
    xl_meta: &[u8],
    declared: &BTreeMap<String, (String, Option<String>)>,
    orphan: &StaleOwnedOrphanReceipt,
    entries: &mut Vec<ShardInventoryEntry>,
) -> Result<()> {
    let mut discovered_declared = BTreeSet::new();
    for (directory_name, is_dir) in contained_directory_entries(object)? {
        if directory_name == "xl.meta" {
            ensure!(!is_dir, "stale object xl.meta is not a regular file");
            continue;
        }
        ensure!(is_dir, "stale object contains an unexpected top-level file");
        let directory = open_beneath(
            object,
            &directory_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let parts = contained_directory_entries(&directory)?;
        ensure!(
            !parts.is_empty(),
            "stale object contains an empty data directory"
        );
        for (part_name, part_is_dir) in parts {
            ensure!(
                !part_is_dir
                    && part_name.strip_prefix("part.").is_some_and(
                        |part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
                    ),
                "stale object data directory contains a non-part entry"
            );
            let relative = format!("{directory_name}/{part_name}");
            let part = open_beneath(object, &relative, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
            let metadata = part
                .metadata()
                .context("stat exhaustively discovered stale shard")?;
            let bytes = read_limited(
                &part,
                MAX_XL_META_BYTES,
                "exhaustively discovered stale shard",
            )?;
            let full_relative = format!("{}/{object_key}/{relative}", request.bucket);
            let (version_id, expected_hash, reference_state) = match declared.get(&relative) {
                Some((version_id, Some(hash))) => {
                    discovered_declared.insert(relative.clone());
                    (
                        version_id.clone(),
                        hash.clone(),
                        FragmentReferenceState::ReferencedVersion,
                    )
                }
                Some((version_id, None)) => {
                    discovered_declared.insert(relative.clone());
                    (
                        version_id.clone(),
                        sha256_bytes(xl_meta),
                        FragmentReferenceState::Unclassified,
                    )
                }
                None if full_relative == orphan.relative_part_path => (
                    orphan.version_id.clone(),
                    orphan.object_sha256.clone(),
                    FragmentReferenceState::OrphanedUncommitted,
                ),
                None => (
                    directory_name.clone(),
                    sha256_bytes(xl_meta),
                    FragmentReferenceState::Unclassified,
                ),
            };
            entries.push(ShardInventoryEntry {
                fragment_id: stale_fragment_id(&request.drive_uuid, &full_relative, metadata.ino()),
                bucket: request.bucket.clone(),
                object_key: object_key.to_string(),
                version_id,
                drive_uuid: request.drive_uuid.clone(),
                object_sha256: expected_hash,
                sha256: sha256_bytes(&bytes),
                reference_state,
            });
            ensure!(
                entries.len() <= MAX_STALE_INVENTORY_ENTRIES,
                "stale inventory entry count exceeds its bound"
            );
        }
    }
    ensure!(
        discovered_declared.len() == declared.len(),
        "XL2 metadata declares a shard part absent from the filesystem traversal"
    );
    Ok(())
}

fn contained_directory_entries(directory: &File) -> Result<Vec<(String, bool)>> {
    let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&path)
        .with_context(|| format!("scan pre-opened stale inventory directory {path}"))?
    {
        let entry = entry.context("read stale inventory directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("stale inventory contains a non-UTF-8 filename"))?;
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "stale inventory contains an unsafe filename"
        );
        let file_type = entry
            .file_type()
            .context("read stale inventory entry type")?;
        ensure!(
            !file_type.is_symlink(),
            "stale inventory contains a symbolic link"
        );
        ensure!(
            file_type.is_dir() || file_type.is_file(),
            "stale inventory contains a non-file, non-directory entry"
        );
        entries.push((name, file_type.is_dir()));
        ensure!(
            entries.len() <= MAX_STALE_INVENTORY_ENTRIES,
            "stale inventory directory exceeds its entry bound"
        );
    }
    entries.sort();
    Ok(entries)
}

fn remove_stale_orphan(
    request: &StaleOfflineHelperRequest,
    root: &File,
    orphan: &StaleOwnedOrphanReceipt,
) -> Result<StaleOfflineHelperResponse> {
    ensure!(
        orphan.run_id == request.run_id
            && orphan.bucket == request.bucket
            && orphan.drive_uuid == request.drive_uuid,
        "refusing to remove an orphan owned by another run or generation"
    );
    let object = open_stale_object_dir(root, &orphan.bucket, &orphan.object_key)?;
    let directory = open_beneath(
        &object,
        &orphan.version_id,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let part = open_beneath(&directory, "part.1", libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    let metadata = part
        .metadata()
        .context("stat owned orphan before removal")?;
    let bytes = read_limited(&part, MAX_XL_META_BYTES, "owned orphan before removal")?;
    ensure!(
        metadata.ino() == orphan.part_inode
            && device_id(&metadata) == orphan.part_device_id
            && metadata.len() == orphan.part_size_bytes
            && sha256_bytes(&bytes) == orphan.fragment_sha256,
        "refusing to remove an orphan whose inode, device, size, or hash changed"
    );
    drop(part);
    let part_c = CString::new("part.1")?;
    let directory_c = CString::new(orphan.version_id.as_str())?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), part_c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("unlink owned stale orphan part");
    }
    directory
        .sync_all()
        .context("fsync emptied stale orphan directory")?;
    drop(directory);
    if unsafe { libc::unlinkat(object.as_raw_fd(), directory_c.as_ptr(), libc::AT_REMOVEDIR) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("remove owned stale orphan directory");
    }
    object
        .sync_all()
        .context("fsync stale object after orphan removal")?;
    root.sync_all()
        .context("fsync stale volume after orphan removal")?;
    Ok(StaleOfflineHelperResponse::OrphanRemoved {
        fragment_id: orphan.fragment_id.clone(),
        removed_at_ms: now_ms()?,
    })
}

impl Default for StorageHelperRoots {
    fn default() -> Self {
        Self {
            volume: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            journal: PathBuf::from(STORAGE_HELPER_JOURNAL_ROOT),
            lock: PathBuf::from(STORAGE_RECOVERY_HOST_LOCK_DIRECTORY),
            host_proc: PathBuf::from("/host/proc"),
            host_dev: PathBuf::from("/host/dev"),
            #[cfg(test)]
            trust_context_host_generation: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageHelperSessionRequest {
    Begin {
        context: Box<OwnedStorageContext>,
    },
    Execute {
        invocation: Box<StorageHelperInvocation>,
    },
    ExecuteMutation {
        operation_id: String,
        invocation: Box<StorageHelperInvocation>,
    },
    QueryMutation {
        context: Box<OwnedStorageContext>,
        operation_id: String,
    },
    StaleExecute {
        context: Box<OwnedStorageContext>,
        request: Box<StaleOfflineHelperRequest>,
    },
    Finish {
        context: Box<OwnedStorageContext>,
        cleanup: Box<StorageRecoveryCleanupProof>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageHelperSessionResponse {
    Ready {
        scope_sha256: String,
    },
    Receipt {
        receipt: Box<StorageRecoveryOperationReceipt>,
    },
    MutationLookup {
        lookup: Box<MutationJournalLookup>,
    },
    MutationJournalAbsent {
        operation_id: String,
    },
    MutationRejectedBeforeJournal {
        message: String,
    },
    StaleResponse {
        response: Box<StaleOfflineHelperResponse>,
    },
    Error {
        message: String,
    },
    Finished {
        scope_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Completed,
    Prepared,
    Mutated,
    Restored,
    VerifiedSuperseded,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationRecoveryState {
    Prepared,
    Mutated,
    Restored,
    VerifiedSuperseded,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationJournalLookup {
    pub operation_id: String,
    pub operation: StorageRecoveryHostOperation,
    pub state: MutationRecoveryState,
    pub receipt: Option<Box<StorageRecoveryOperationReceipt>>,
    pub observed_at_ms: u64,
}

impl MutationJournalLookup {
    pub fn validate_for(
        &self,
        context: &OwnedStorageContext,
        operation_id: &str,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<()> {
        ensure!(
            self.operation_id == operation_id
                && self.operation == *operation
                && matches!(operation, StorageRecoveryHostOperation::MutateShard { .. })
                && self.observed_at_ms >= context.exclusive_access.kubernetes_lease.acquired_at_ms,
            "mutation lookup does not match the owned operation"
        );
        if let Some(receipt) = &self.receipt {
            receipt.validate_for(context, operation)?;
            ensure!(
                receipt.operation_id == operation_id
                    && matches!(
                        self.state,
                        MutationRecoveryState::Mutated
                            | MutationRecoveryState::Restored
                            | MutationRecoveryState::VerifiedSuperseded
                    ),
                "mutation lookup receipt does not describe a completed mutation"
            );
        } else {
            ensure!(
                self.state == MutationRecoveryState::Prepared,
                "mutation lookup omitted a receipt outside the prepared state"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MutationJournal {
    schema_version: u8,
    operation_id: String,
    context_sha256: String,
    scope_sha256: String,
    lease_uid: String,
    lease_acquired_at_ms: u64,
    #[serde(default)]
    holder_identity: String,
    operation: StorageRecoveryHostOperation,
    state: JournalState,
    relative_part_path: Option<String>,
    shard_device_id: Option<String>,
    shard_inode: Option<u64>,
    shard_size_bytes: Option<u64>,
    byte_offset: Option<u64>,
    original_byte: Option<u8>,
    mutated_byte: Option<u8>,
    original_sha256: Option<String>,
    mutated_sha256: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    terminal_post_inspection_operation_id: Option<String>,
    #[serde(default)]
    response_body: Option<String>,
    #[serde(default)]
    response_sha256: Option<String>,
    #[serde(default)]
    started_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineXl2InspectResponse {
    pub mount_device_id: String,
    pub drive_uuid: String,
    pub format_json_sha256: String,
    pub xl_meta_sha256: String,
    pub layout: crate::fault::xl2_inspector::Xl2ObjectVersionLayout,
    pub selected_part: OfflineInspectedShard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineInspectedShard {
    pub part_number: u32,
    pub relative_part_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub original_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshVolumeShardInspectionRequest {
    pub volume_root: PathBuf,
    pub deployment_id: String,
    pub drive_uuid: String,
    pub mount_device_id: String,
    pub object_directory: String,
    pub bucket: String,
    pub object_key: String,
    pub object_sha256: String,
    pub version_id: String,
    pub selected_part_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshVolumeShardInspectionResponse {
    pub observed_at_ms: u64,
    pub inspection: OfflineXl2InspectResponse,
}

pub fn inspect_fresh_volume_shard(
    request: &FreshVolumeShardInspectionRequest,
) -> Result<FreshVolumeShardInspectionResponse> {
    ensure!(
        request.volume_root == Path::new(STORAGE_HELPER_VOLUME_ROOT),
        "fresh-volume shard inspection must use the fixed helper volume root"
    );
    let operation = StorageRecoveryHostOperation::InspectXlMeta {
        object_directory: request.object_directory.clone(),
        bucket: request.bucket.clone(),
        object_key: request.object_key.clone(),
        object_sha256: request.object_sha256.clone(),
        version_id: request.version_id.clone(),
        selected_part_number: request.selected_part_number,
        expected_mount_device_id: request.mount_device_id.clone(),
        expected_drive_uuid: request.drive_uuid.clone(),
    };
    operation.validate()?;
    ensure!(
        request.object_directory == format!("{}/{}", request.bucket, request.object_key)
            && request.selected_part_number == 1,
        "fresh-volume shard inspection target does not match the sealed object part"
    );
    let root = open_directory(&request.volume_root, "fresh-volume shard inspection root")?;
    let metadata = root
        .metadata()
        .context("stat fresh-volume shard inspection root")?;
    ensure!(
        device_id(&metadata) == request.mount_device_id,
        "fresh-volume shard inspection root device changed"
    );
    let inspection = inspect_response(
        &root,
        &request.deployment_id,
        &request.object_directory,
        &request.version_id,
        request.selected_part_number,
        &request.mount_device_id,
        &request.drive_uuid,
    )?;
    Ok(FreshVolumeShardInspectionResponse {
        observed_at_ms: now_ms()?,
        inspection,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfflineShardMutationResponse {
    pub journal_operation_id: String,
    pub relative_part_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub byte_offset: u64,
    pub original_byte: u8,
    pub mutated_byte: u8,
    pub original_sha256: String,
    pub mutated_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfflineShardRecoveryResponse {
    pub mutation_operation_id: String,
    pub outcome: crate::fault::storage_recovery_runtime::RestoreOutcome,
    pub observed_sha256: Option<String>,
}

pub struct StorageHelperSession {
    owner: OwnedStorageContext,
    roots: StorageHelperRoots,
    volume_root: File,
    journal_root: File,
    _lock: File,
    mutation_started: bool,
}

impl Drop for StorageHelperSession {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl StorageHelperSession {
    pub fn begin_default(context: OwnedStorageContext) -> Result<Self> {
        Self::begin(context, &StorageHelperRoots::default())
    }

    pub fn begin(context: OwnedStorageContext, roots: &StorageHelperRoots) -> Result<Self> {
        context.validate()?;
        ensure!(
            now_ms()? < context.exclusive_access.kubernetes_lease.expires_at_ms,
            "storage-recovery Kubernetes Lease expired before helper session"
        );
        let lock_root = open_directory(&roots.lock, "storage helper lock root")?;
        let lock_name = format!("storage-{}.lock", context.scope_sha256);
        let lock = open_beneath(
            &lock_root,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )?;
        acquire_flock(&lock)?;
        let lock_metadata = lock.metadata().context("stat storage helper flock")?;
        ensure!(
            device_id(&lock_metadata) == context.exclusive_access.host_flock.device_id
                && lock_metadata.ino() == context.exclusive_access.host_flock.inode,
            "storage helper flock identity differs from the owned context"
        );
        let volume_root = open_directory(&roots.volume, "storage helper volume root")?;
        let volume_metadata = volume_root
            .metadata()
            .context("stat storage helper volume root")?;
        ensure!(
            device_id(&volume_metadata) == context.host_generation.device_major_minor,
            "storage helper volume root device differs from the owned context"
        );
        let journal_root = open_directory(&roots.journal, "storage helper journal root")?;
        ensure_no_unresolved_journals(&journal_root, &context)?;
        Ok(Self {
            owner: context,
            roots: roots.clone(),
            volume_root,
            journal_root,
            _lock: lock,
            mutation_started: false,
        })
    }

    pub fn execute(
        &mut self,
        invocation: StorageHelperInvocation,
    ) -> Result<StorageRecoveryOperationReceipt> {
        let operation_id = Uuid::new_v4().to_string();
        self.execute_with_mutation_operation_id(invocation, &operation_id)
    }

    pub fn execute_mutation_with_id(
        &mut self,
        invocation: StorageHelperInvocation,
        operation_id: &str,
    ) -> Result<StorageRecoveryOperationReceipt> {
        ensure!(
            matches!(
                invocation.operation,
                StorageRecoveryHostOperation::MutateShard { .. }
            ),
            "explicit helper operationId is restricted to shard mutation"
        );
        self.execute_with_mutation_operation_id(invocation, operation_id)
    }

    fn execute_with_mutation_operation_id(
        &mut self,
        invocation: StorageHelperInvocation,
        mutation_operation_id: &str,
    ) -> Result<StorageRecoveryOperationReceipt> {
        Uuid::parse_str(mutation_operation_id)
            .context("storage helper mutation operationId is not a UUID")?;
        validate_session_context(&self.owner, &invocation.context)?;
        invocation.operation.validate()?;
        let started_at_ms = now_ms()?;
        let is_shard_mutation = matches!(
            &invocation.operation,
            StorageRecoveryHostOperation::MutateShard { .. }
        );
        if matches!(
            &invocation.operation,
            StorageRecoveryHostOperation::MutateShard { .. }
                | StorageRecoveryHostOperation::RestoreShard { .. }
                | StorageRecoveryHostOperation::VerifySupersededShard { .. }
                | StorageRecoveryHostOperation::DetachDeviceMapper { .. }
                | StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
        ) {
            // The intentional EIO table blocks format.json until reattach.
            // Mount, filesystem, DM UUID, and exact isolation-table identity
            // still bind the operation to the sealed physical generation.
            let format_readable = !matches!(
                &invocation.operation,
                StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
            );
            let observed =
                observe_current_host_generation(&invocation.context, &self.roots, format_readable)?;
            let mut expected = invocation.context.host_generation.clone();
            if let StorageRecoveryHostOperation::ReattachDeviceMapper {
                isolation_table, ..
            } = &invocation.operation
            {
                expected.device_mapper_table_sha256 =
                    Some(sha256_bytes(canonical_table(isolation_table)?.as_bytes()));
            }
            ensure!(
                observed == expected,
                "storage helper host generation drifted before destructive operation"
            );
        }
        if matches!(
            &invocation.operation,
            StorageRecoveryHostOperation::PrepareFreshVolume { .. }
                | StorageRecoveryHostOperation::DetachDeviceMapper { .. }
                | StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
        ) {
            self.mutation_started = true;
        }
        let result = match &invocation.operation {
            StorageRecoveryHostOperation::InspectHostGeneration => {
                let observed =
                    observe_current_host_generation(&invocation.context, &self.roots, true)?;
                completed_receipt(
                    &invocation.context,
                    &self.journal_root,
                    invocation.operation.clone(),
                    &observed,
                    started_at_ms,
                )
            }
            StorageRecoveryHostOperation::InspectXlMeta {
                object_directory,
                bucket,
                object_key,
                object_sha256,
                version_id,
                selected_part_number,
                expected_mount_device_id,
                expected_drive_uuid,
            } => inspect(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                object_directory,
                bucket,
                object_key,
                object_sha256,
                version_id,
                *selected_part_number,
                expected_mount_device_id,
                expected_drive_uuid,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::MutateShard { .. } => mutate(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                &invocation.operation,
                mutation_operation_id,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::RestoreShard {
                mutation_operation_id,
            } => restore(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                &invocation.operation,
                mutation_operation_id,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::VerifySupersededShard { .. } => verify_superseded(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                &invocation.operation,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::PrepareFreshVolume {
                replacement_persistent_volume,
                replacement_persistent_volume_claim,
            } => completed_receipt(
                &invocation.context,
                &self.journal_root,
                invocation.operation.clone(),
                &serde_json::json!({
                    "outcome": "prepared-by-fixture-adapter",
                    "persistentVolume": replacement_persistent_volume,
                    "persistentVolumeClaim": replacement_persistent_volume_claim,
                }),
                started_at_ms,
            ),
            StorageRecoveryHostOperation::DetachDeviceMapper { .. }
            | StorageRecoveryHostOperation::ReattachDeviceMapper { .. } => {
                transition_device_mapper(
                    &invocation.context,
                    &self.journal_root,
                    &invocation.operation,
                    started_at_ms,
                )
            }
        };
        if is_shard_mutation {
            self.mutation_started = result.is_ok()
                || self
                    .mutation_journal_exists(mutation_operation_id)
                    .unwrap_or(true);
        }
        result
    }

    pub fn query_mutation(
        &self,
        context: &OwnedStorageContext,
        operation_id: &str,
    ) -> Result<MutationJournalLookup> {
        Uuid::parse_str(operation_id)
            .context("storage helper mutation lookup operationId is not a UUID")?;
        validate_session_context(&self.owner, context)?;
        let journal = load_journal(&self.journal_root, operation_id)?;
        ensure!(
            journal.schema_version == 1
                && journal.operation_id == operation_id
                && journal.context_sha256 == context_sha256(context)?
                && journal.scope_sha256 == context.scope_sha256
                && journal.lease_uid == context.exclusive_access.kubernetes_lease.uid
                && journal.lease_acquired_at_ms
                    == context.exclusive_access.kubernetes_lease.acquired_at_ms
                && journal.holder_identity
                    == context.exclusive_access.kubernetes_lease.holder_identity
                && matches!(
                    journal.operation,
                    StorageRecoveryHostOperation::MutateShard { .. }
                ),
            "mutation lookup journal belongs to another operation or context"
        );
        let state = match journal.state {
            JournalState::Prepared => MutationRecoveryState::Prepared,
            JournalState::Mutated => MutationRecoveryState::Mutated,
            JournalState::Restored => MutationRecoveryState::Restored,
            JournalState::VerifiedSuperseded => MutationRecoveryState::VerifiedSuperseded,
            JournalState::Quarantined => MutationRecoveryState::Quarantined,
            JournalState::Completed => bail!("mutation lookup journal has an invalid state"),
        };
        let receipt = if state == MutationRecoveryState::Prepared {
            None
        } else {
            let response_body = required(&journal.response_body, "mutation response body")?;
            ensure!(
                journal.response_sha256.as_deref()
                    == Some(sha256_bytes(response_body.as_bytes()).as_str()),
                "mutation lookup response digest mismatch"
            );
            Some(Box::new(receipt(
                context,
                journal.operation.clone(),
                operation_id.to_string(),
                response_body.to_string(),
                journal.started_at_ms,
                journal.updated_at_ms,
            )?))
        };
        let lookup = MutationJournalLookup {
            operation_id: operation_id.to_string(),
            operation: journal.operation,
            state,
            receipt,
            observed_at_ms: now_ms()?,
        };
        lookup.validate_for(context, operation_id, &lookup.operation)?;
        Ok(lookup)
    }

    pub fn mutation_journal_exists(&self, operation_id: &str) -> Result<bool> {
        let name = CString::new(journal_name(operation_id)?)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.journal_root.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(error).context("inspect storage mutation journal after helper rejection")
        }
    }

    pub fn execute_stale(
        &mut self,
        context: &OwnedStorageContext,
        request: &StaleOfflineHelperRequest,
    ) -> Result<StaleOfflineHelperResponse> {
        validate_session_context(&self.owner, context)?;
        validate_stale_helper_request(request, true)?;
        ensure!(
            context.case == crate::fault::storage_recovery::StorageRecoveryCase::StaleDiskReturn
                && request.run_id == context.identity.run_id
                && request.scenario == context.identity.scenario
                && request.deployment_id == context.volume.rustfs_deployment_id
                && request.drive_uuid == context.volume.rustfs_drive_uuid
                && request.filesystem_uuid == context.volume.filesystem_uuid
                && request.bucket == context.identity.bucket,
            "stale helper request is not bound to the owned storage context"
        );
        if matches!(
            &request.operation,
            StaleOfflineHelperOperation::InjectOrphan { .. }
                | StaleOfflineHelperOperation::RemoveOwnedOrphan { .. }
        ) {
            self.mutation_started = true;
        }
        execute_stale_offline_helper_at_root(request, &self.volume_root)
    }

    pub fn finish(
        &self,
        context: &OwnedStorageContext,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        validate_session_context(&self.owner, context)?;
        ensure!(
            !matches!(
                cleanup,
                StorageRecoveryCleanupProof::AbortedBeforeMutation { .. }
            ) || !self.mutation_started,
            "pre-mutation abort proof cannot close a helper session after mutation began"
        );
        cleanup.validate_for(context)
    }
}

fn observe_current_host_generation(
    context: &OwnedStorageContext,
    roots: &StorageHelperRoots,
    require_format: bool,
) -> Result<HostGenerationIdentity> {
    #[cfg(test)]
    if roots.trust_context_host_generation {
        return Ok(context.host_generation.clone());
    }

    let probe = run_fresh_volume_host_probe(&FreshVolumeHostProbeRequest {
        target_container_id: context.volume.rustfs_container_id.clone(),
        target_mount_path: context.volume.mount_path.clone(),
        volume_root: roots.volume.clone(),
        host_proc_root: roots.host_proc.clone(),
        host_dev_root: roots.host_dev.clone(),
        lock_path: roots
            .lock
            .join(format!("storage-{}.lock", context.scope_sha256)),
        require_format,
        skip_format_read: !require_format,
        scan_empty: false,
    })?;
    ensure!(
        probe.canonical_device == context.volume.canonical_device,
        "storage helper canonical device drifted"
    );
    let rustfs_drive_uuid = match probe.rustfs_drive_uuid {
        Some(drive_uuid) => drive_uuid,
        None if !require_format => context.host_generation.rustfs_drive_uuid.clone(),
        None => bail!("storage helper format.json drive UUID is absent"),
    };
    let (device_mapper_uuid, device_mapper_table_sha256) =
        if context.host_generation.device_mapper_uuid.is_some() {
            let (major, minor) = probe
                .device_major_minor
                .split_once(':')
                .context("storage helper device major:minor is malformed")?;
            let info = run_dmsetup(&[
                "info",
                "--columns",
                "--noheadings",
                "--separator",
                "|",
                "--options",
                "name,uuid",
                "-j",
                major,
                "-m",
                minor,
            ])?;
            require_dm_success(&info, "host generation query")?;
            let lines = info.stdout.trim().lines().collect::<Vec<_>>();
            ensure!(
                lines.len() == 1,
                "storage helper device-mapper identity is ambiguous"
            );
            let (mapping_name, uuid) = lines[0]
                .split_once('|')
                .context("storage helper device-mapper identity is malformed")?;
            let mapping_name = mapping_name.trim();
            let uuid = uuid.trim();
            ensure!(
                !mapping_name.is_empty() && !uuid.is_empty(),
                "storage helper device-mapper identity is empty"
            );
            let table = run_dmsetup(&["table", "--showkeys", mapping_name])?;
            require_dm_success(&table, "host generation table query")?;
            let table = canonical_table(&table.stdout)?;
            (Some(uuid.to_string()), Some(sha256_bytes(table.as_bytes())))
        } else {
            (None, None)
        };
    Ok(HostGenerationIdentity {
        mount_id: probe.mount_id,
        mount_namespace_id: probe.mount_namespace_id,
        device_major_minor: probe.device_major_minor,
        device_mapper_uuid,
        device_mapper_table_sha256,
        filesystem_uuid: probe.filesystem_uuid,
        rustfs_drive_uuid,
    })
}

fn transition_device_mapper(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    ensure!(
        context.case == crate::fault::storage_recovery::StorageRecoveryCase::StaleDiskReturn,
        "device-mapper transition is restricted to stale-disk-return"
    );
    let (action, mapping_name, generation_sha256, recovery_table, isolation_table) = match operation
    {
        StorageRecoveryHostOperation::DetachDeviceMapper {
            mapping_name,
            expected_generation_sha256,
            recovery_table,
            isolation_table,
        } => (
            StaleDeviceMapperAction::Isolate,
            mapping_name,
            expected_generation_sha256,
            recovery_table,
            isolation_table,
        ),
        StorageRecoveryHostOperation::ReattachDeviceMapper {
            mapping_name,
            expected_generation_sha256,
            recovery_table,
            isolation_table,
        } => (
            StaleDeviceMapperAction::Reattach,
            mapping_name,
            expected_generation_sha256,
            recovery_table,
            isolation_table,
        ),
        _ => unreachable!("transition_device_mapper receives only DM operations"),
    };
    let plan = StaleDeviceMapperPlan::new(
        mapping_name,
        generation_sha256,
        recovery_table,
        isolation_table,
    )?;
    ensure!(
        host_generation_sha256(&context.host_generation)? == *generation_sha256
            && context
                .host_generation
                .device_mapper_table_sha256
                .as_deref()
                == Some(plan.recovery_table_sha256.as_str()),
        "device-mapper transition is not bound to the owned host generation"
    );
    let (expected_before, target_table) = match action {
        StaleDeviceMapperAction::Isolate => (&plan.recovery_table, &plan.isolation_table),
        StaleDeviceMapperAction::Reattach => (&plan.isolation_table, &plan.recovery_table),
    };
    let mut commands = Vec::with_capacity(5);
    let before = run_dmsetup(&["table", "--showkeys", mapping_name])?;
    let observed_before = canonical_table(&before.stdout)?;
    commands.push(before);
    ensure!(
        observed_before == *expected_before,
        "device-mapper table drifted before stale transition"
    );

    let mut transition_started = false;
    let transition_result = (|| -> Result<()> {
        let suspend = run_dmsetup(&["suspend", "--noflush", mapping_name])?;
        transition_started = suspend.exit_code == 0;
        require_dm_success(&suspend, "suspend")?;
        commands.push(suspend);

        let reload = run_dmsetup(&["reload", mapping_name, "--table", target_table])?;
        require_dm_success(&reload, "reload")?;
        commands.push(reload);

        let resume = run_dmsetup(&["resume", mapping_name])?;
        require_dm_success(&resume, "resume")?;
        commands.push(resume);
        Ok(())
    })();
    if let Err(primary) = transition_result {
        if transition_started {
            let recovery = recover_dm_linear(mapping_name, &plan.recovery_table);
            return match recovery {
                Ok(()) => Err(primary.context("stale DM transition failed; linear table restored")),
                Err(recovery_error) => Err(primary.context(format!(
                    "stale DM transition failed and bounded linear restore also failed: {recovery_error:#}"
                ))),
            };
        }
        return Err(primary);
    }

    let after = run_dmsetup(&["table", "--showkeys", mapping_name])?;
    let observed_after = canonical_table(&after.stdout)?;
    require_dm_success(&after, "post-transition table query")?;
    commands.push(after);
    if observed_after != *target_table {
        let primary = anyhow::anyhow!("device-mapper post-transition table differs from target");
        return match recover_dm_linear(mapping_name, &plan.recovery_table) {
            Ok(()) => Err(primary.context("linear table restored after verification failure")),
            Err(recovery_error) => Err(primary.context(format!(
                "bounded linear restore failed after verification failure: {recovery_error:#}"
            ))),
        };
    }
    let response = StaleDeviceMapperTransitionResponse {
        action,
        mapping_name: mapping_name.clone(),
        generation_sha256: generation_sha256.clone(),
        before_table: observed_before.clone(),
        before_table_sha256: sha256_bytes(observed_before.as_bytes()),
        after_table: observed_after.clone(),
        after_table_sha256: sha256_bytes(observed_after.as_bytes()),
        commands,
    };
    completed_receipt(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
    )
}

fn run_dmsetup(args: &[&str]) -> Result<DeviceMapperCommandReceipt> {
    let started_at_ms = now_ms()?;
    let output = Command::new("timeout")
        .args(["--signal=KILL", "5s", "dmsetup"])
        .args(args)
        .output()
        .context("execute bounded dmsetup command")?;
    let completed_at_ms = now_ms()?;
    Ok(DeviceMapperCommandReceipt {
        argv: std::iter::once("dmsetup".to_string())
            .chain(args.iter().map(|arg| (*arg).to_string()))
            .collect(),
        exit_code: output.status.code().unwrap_or(137),
        stdout: String::from_utf8(output.stdout).context("dmsetup stdout is not UTF-8")?,
        stderr: String::from_utf8(output.stderr).context("dmsetup stderr is not UTF-8")?,
        started_at_ms,
        completed_at_ms,
    })
}

fn require_dm_success(receipt: &DeviceMapperCommandReceipt, action: &str) -> Result<()> {
    ensure!(
        receipt.exit_code == 0 && receipt.stderr.trim().is_empty(),
        "dmsetup {action} failed: exit={} stderr={:?}",
        receipt.exit_code,
        receipt.stderr
    );
    Ok(())
}

fn canonical_table(table: &str) -> Result<String> {
    ensure!(
        !table.contains('\n') || table.trim_end().lines().count() == 1,
        "device-mapper table contains multiple targets"
    );
    let canonical = table.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(!canonical.is_empty(), "device-mapper table is empty");
    Ok(canonical)
}

fn recover_dm_linear(mapping_name: &str, recovery_table: &str) -> Result<()> {
    let state = run_dmsetup(&[
        "info",
        "--columns",
        "--noheadings",
        "--options",
        "suspended",
        mapping_name,
    ])?;
    require_dm_success(&state, "recovery state query")?;
    let suspended = match state.stdout.trim().to_ascii_lowercase().as_str() {
        "suspended" | "yes" | "y" | "1" => true,
        "active" | "no" | "n" | "0" => false,
        other => bail!("bounded DM recovery observed unsupported state {other:?}"),
    };
    if !suspended {
        let suspend = run_dmsetup(&["suspend", "--noflush", mapping_name])?;
        require_dm_success(&suspend, "recovery suspend")?;
    }
    let reload = run_dmsetup(&["reload", mapping_name, "--table", recovery_table])?;
    require_dm_success(&reload, "recovery reload")?;
    let resume = run_dmsetup(&["resume", mapping_name])?;
    require_dm_success(&resume, "recovery resume")?;
    let observed = run_dmsetup(&["table", "--showkeys", mapping_name])?;
    require_dm_success(&observed, "recovery table query")?;
    ensure!(
        canonical_table(&observed.stdout)? == recovery_table,
        "bounded DM recovery did not restore the exact linear table"
    );
    Ok(())
}

fn validate_session_context(
    owner: &OwnedStorageContext,
    current: &OwnedStorageContext,
) -> Result<()> {
    current.validate()?;
    ensure!(
        owner.identity == current.identity
            && owner.case == current.case
            && owner.attempt_id == current.attempt_id
            && owner.cluster_context == current.cluster_context
            && owner.tenant_uid == current.tenant_uid
            && owner.scope_sha256 == current.scope_sha256
            && same_storage_volume_generation(&owner.volume, &current.volume)
            && owner.resource_versions == current.resource_versions
            && owner.host_generation == current.host_generation
            && owner.exclusive_access.host_flock == current.exclusive_access.host_flock
            && owner.exclusive_access.kubernetes_lease.name
                == current.exclusive_access.kubernetes_lease.name
            && owner.exclusive_access.kubernetes_lease.uid
                == current.exclusive_access.kubernetes_lease.uid
            && owner.exclusive_access.kubernetes_lease.holder_identity
                == current.exclusive_access.kubernetes_lease.holder_identity
            && owner.exclusive_access.kubernetes_lease.scope_sha256
                == current.exclusive_access.kubernetes_lease.scope_sha256
            && owner.exclusive_access.kubernetes_lease.acquired_at_ms
                == current.exclusive_access.kubernetes_lease.acquired_at_ms
            && current.exclusive_access.kubernetes_lease.renew_at_ms
                >= owner.exclusive_access.kubernetes_lease.renew_at_ms
            && owner.helper_pod_name == current.helper_pod_name
            && owner.helper_pod_uid == current.helper_pod_uid,
        "storage helper session ownership or physical target changed"
    );
    ensure!(
        current.exclusive_access.kubernetes_lease.expires_at_ms > now_ms()?,
        "storage helper session Lease snapshot expired"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inspect(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    object_directory: &str,
    bucket: &str,
    object_key: &str,
    object_sha256: &str,
    version_id: &str,
    selected_part_number: u32,
    expected_mount_device_id: &str,
    expected_drive_uuid: &str,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    ensure!(
        expected_mount_device_id == context.host_generation.device_major_minor
            && expected_drive_uuid == context.volume.rustfs_drive_uuid,
        "offline inspection target differs from the owned context"
    );
    ensure!(
        bucket == context.identity.bucket && !object_key.trim().is_empty(),
        "offline inspection object identity differs from the owned context"
    );
    let response = inspect_response(
        volume_root,
        &context.volume.rustfs_deployment_id,
        object_directory,
        version_id,
        selected_part_number,
        expected_mount_device_id,
        expected_drive_uuid,
    )?;
    completed_receipt(
        context,
        journal_root,
        StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: object_directory.to_string(),
            bucket: bucket.to_string(),
            object_key: object_key.to_string(),
            object_sha256: object_sha256.to_string(),
            version_id: version_id.to_string(),
            selected_part_number,
            expected_mount_device_id: expected_mount_device_id.to_string(),
            expected_drive_uuid: expected_drive_uuid.to_string(),
        },
        &response,
        started_at_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_response(
    volume_root: &File,
    deployment_id: &str,
    object_directory: &str,
    version_id: &str,
    selected_part_number: u32,
    expected_mount_device_id: &str,
    expected_drive_uuid: &str,
) -> Result<OfflineXl2InspectResponse> {
    let format_file = open_beneath(
        volume_root,
        FORMAT_JSON_PATH,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let format_bytes = read_limited(&format_file, MAX_FORMAT_JSON_BYTES, "format.json")?;
    validate_format_json_drive(&format_bytes, deployment_id, expected_drive_uuid)?;
    let xl_meta_path = format!("{object_directory}/xl.meta");
    let xl_meta_file = open_beneath(
        volume_root,
        &xl_meta_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let xl_meta_metadata = xl_meta_file.metadata().context("stat contained xl.meta")?;
    ensure!(
        device_id(&xl_meta_metadata) == expected_mount_device_id,
        "contained xl.meta crossed the proven volume device"
    );
    let xl_meta = read_limited(&xl_meta_file, MAX_XL_META_BYTES, "xl.meta")?;
    let mut layout = inspect_xl_meta(&xl_meta, version_id)?;
    for relative_part_path in &mut layout.relative_part_paths {
        *relative_part_path = format!("{object_directory}/{relative_part_path}");
    }
    let selected_index = layout
        .part_numbers
        .iter()
        .position(|part| *part == selected_part_number)
        .context("selected part number is absent from XL2 metadata")?;
    let relative_part_path = layout
        .relative_part_paths
        .get(selected_index)
        .context("selected XL2 part path is absent")?
        .clone();
    let part = open_beneath(
        volume_root,
        &relative_part_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let part_metadata = part.metadata().context("stat inspected shard")?;
    ensure!(part_metadata.len() > 0, "selected shard is empty");
    validate_part_identity(
        &part,
        expected_mount_device_id,
        part_metadata.ino(),
        part_metadata.len(),
    )?;
    Ok(OfflineXl2InspectResponse {
        mount_device_id: expected_mount_device_id.to_string(),
        drive_uuid: expected_drive_uuid.to_string(),
        format_json_sha256: sha256_bytes(&format_bytes),
        xl_meta_sha256: sha256_bytes(&xl_meta),
        layout,
        selected_part: OfflineInspectedShard {
            part_number: selected_part_number,
            relative_part_path,
            shard_device_id: device_id(&part_metadata),
            shard_inode: part_metadata.ino(),
            shard_size_bytes: part_metadata.len(),
            original_sha256: hash_file(&part, None)?,
        },
    })
}

fn mutate(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    operation_id: &str,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let StorageRecoveryHostOperation::MutateShard {
        inspection_operation_id,
        part_number,
        byte_offset,
    } = operation
    else {
        unreachable!("mutate receives only MutateShard")
    };
    let inspection = load_journal(journal_root, inspection_operation_id)?;
    inspection.operation.validate()?;
    ensure!(
        inspection.schema_version == 1
            && inspection.operation_id == *inspection_operation_id
            && inspection.context_sha256 == context_sha256(context)?
            && inspection.scope_sha256 == context.scope_sha256
            && inspection.lease_uid == context.exclusive_access.kubernetes_lease.uid
            && inspection.lease_acquired_at_ms
                == context.exclusive_access.kubernetes_lease.acquired_at_ms
            && inspection.holder_identity
                == context.exclusive_access.kubernetes_lease.holder_identity
            && inspection.state == JournalState::Completed,
        "shard mutation inspection receipt is absent, unresolved, or belongs to another context"
    );
    let StorageRecoveryHostOperation::InspectXlMeta {
        selected_part_number,
        ..
    } = &inspection.operation
    else {
        bail!("shard mutation source journal is not an XL2 inspection")
    };
    let inspection_body = required(&inspection.response_body, "inspection response body")?;
    ensure!(
        inspection
            .response_sha256
            .as_deref()
            .is_some_and(|digest| digest == sha256_bytes(inspection_body.as_bytes())),
        "shard mutation inspection response is not durably digest-bound"
    );
    let inspected: OfflineXl2InspectResponse =
        serde_json::from_str(inspection_body).context("decode sealed XL2 inspection response")?;
    let shard = &inspected.selected_part;
    ensure!(
        *selected_part_number == *part_number
            && shard.part_number == *part_number
            && inspected
                .layout
                .part_numbers
                .iter()
                .position(|number| number == part_number)
                .and_then(|index| inspected.layout.relative_part_paths.get(index))
                == Some(&shard.relative_part_path)
            && shard
                .relative_part_path
                .ends_with(&format!("/part.{part_number}"))
            && shard.shard_device_id == context.host_generation.device_major_minor
            && *byte_offset < shard.shard_size_bytes,
        "shard mutation does not match the selected part in the sealed inspection receipt"
    );
    let part = open_beneath(
        volume_root,
        &shard.relative_part_path,
        libc::O_RDWR | libc::O_CLOEXEC,
        0,
    )?;
    validate_part_identity(
        &part,
        &shard.shard_device_id,
        shard.shard_inode,
        shard.shard_size_bytes,
    )?;
    let observed_original = hash_file(&part, None)?;
    ensure!(
        observed_original == shard.original_sha256,
        "shard hash drifted before mutation"
    );
    let mut original = [0_u8; 1];
    ensure!(
        part.read_at(&mut original, *byte_offset)? == 1,
        "short read at shard mutation offset"
    );
    let mutated = original[0] ^ CONTROLLED_SHARD_XOR_MASK;
    let expected_mutated_sha256 = hash_file(&part, Some((*byte_offset, mutated)))?;
    ensure!(
        expected_mutated_sha256 != observed_original,
        "controlled shard mutation would not change the shard digest"
    );

    let prepared_at_ms = now_ms()?;
    let mut journal = MutationJournal {
        schema_version: 1,
        operation_id: operation_id.to_string(),
        context_sha256: context_sha256(context)?,
        scope_sha256: context.scope_sha256.clone(),
        lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
        lease_acquired_at_ms: context.exclusive_access.kubernetes_lease.acquired_at_ms,
        holder_identity: context
            .exclusive_access
            .kubernetes_lease
            .holder_identity
            .clone(),
        operation: operation.clone(),
        state: JournalState::Prepared,
        relative_part_path: Some(shard.relative_part_path.clone()),
        shard_device_id: Some(shard.shard_device_id.clone()),
        shard_inode: Some(shard.shard_inode),
        shard_size_bytes: Some(shard.shard_size_bytes),
        byte_offset: Some(*byte_offset),
        original_byte: Some(original[0]),
        mutated_byte: Some(mutated),
        original_sha256: Some(observed_original.clone()),
        mutated_sha256: Some(expected_mutated_sha256.clone()),
        reason: None,
        terminal_post_inspection_operation_id: None,
        response_body: None,
        response_sha256: None,
        started_at_ms,
        updated_at_ms: prepared_at_ms,
    };
    persist_journal(journal_root, &journal)?;

    ensure!(
        part.write_at(&[mutated], *byte_offset)? == 1,
        "short pwrite during shard mutation"
    );
    part.sync_all().context("fsync mutated shard")?;
    validate_part_identity(
        &part,
        &shard.shard_device_id,
        shard.shard_inode,
        shard.shard_size_bytes,
    )?;
    let mut readback = [0_u8; 1];
    ensure!(
        part.read_at(&mut readback, *byte_offset)? == 1 && readback[0] == mutated,
        "mutated shard byte did not survive fsync/readback"
    );
    let mutated_sha256 = hash_file(&part, None)?;
    ensure!(
        mutated_sha256 == expected_mutated_sha256,
        "mutated shard digest differs from the precomputed controlled mutation"
    );
    let response = OfflineShardMutationResponse {
        journal_operation_id: operation_id.to_string(),
        relative_part_path: shard.relative_part_path.clone(),
        shard_device_id: shard.shard_device_id.clone(),
        shard_inode: shard.shard_inode,
        shard_size_bytes: shard.shard_size_bytes,
        byte_offset: *byte_offset,
        original_byte: original[0],
        mutated_byte: mutated,
        original_sha256: observed_original,
        mutated_sha256,
    };
    let response_body = serde_json::to_string(&response)?;
    journal.state = JournalState::Mutated;
    let persisted_at_ms = persist_response(journal_root, &mut journal, &response_body)?;
    receipt(
        context,
        operation.clone(),
        operation_id.to_string(),
        response_body,
        started_at_ms,
        persisted_at_ms,
    )
}

fn restore(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    mutation_operation_id: &str,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let mut journal = load_journal(journal_root, mutation_operation_id)?;
    ensure!(
        journal.schema_version == 1
            && journal.operation_id == mutation_operation_id
            && journal.context_sha256 == context_sha256(context)?
            && journal.scope_sha256 == context.scope_sha256
            && journal.lease_uid == context.exclusive_access.kubernetes_lease.uid
            && journal.lease_acquired_at_ms
                == context.exclusive_access.kubernetes_lease.acquired_at_ms
            && journal.holder_identity == context.exclusive_access.kubernetes_lease.holder_identity
            && matches!(
                journal.operation,
                StorageRecoveryHostOperation::MutateShard { .. }
            ),
        "mutation journal is not owned by this exact context"
    );
    if matches!(
        journal.state,
        JournalState::Restored | JournalState::VerifiedSuperseded
    ) {
        let original_sha256 =
            validate_terminal_repaired_shard(context, volume_root, journal_root, &journal)?;
        let response = OfflineShardRecoveryResponse {
            mutation_operation_id: mutation_operation_id.to_string(),
            outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired,
            observed_sha256: Some(original_sha256),
        };
        return completed_receipt_with_id(
            context,
            journal_root,
            operation.clone(),
            &response,
            started_at_ms,
            terminal_cleanup_operation_id(operation),
        );
    }
    ensure!(
        matches!(
            journal.state,
            JournalState::Prepared | JournalState::Mutated
        ),
        "mutation journal is not recoverable by this exact context"
    );
    let path = required(&journal.relative_part_path, "journal shard path")?;
    let expected_device = required(&journal.shard_device_id, "journal shard device")?;
    let expected_inode = journal.shard_inode.context("journal lacks shard inode")?;
    let expected_size = journal
        .shard_size_bytes
        .context("journal lacks shard size")?;
    let offset = journal.byte_offset.context("journal lacks byte offset")?;
    let original_byte = journal
        .original_byte
        .context("journal lacks original byte")?;
    let mutated_byte = journal.mutated_byte.context("journal lacks mutated byte")?;
    let original_sha256 = required(&journal.original_sha256, "journal original digest")?;
    let mutated_sha256 = required(&journal.mutated_sha256, "journal mutated digest")?;

    let part = open_beneath(volume_root, path, libc::O_RDWR | libc::O_CLOEXEC, 0)?;
    if let Err(error) =
        validate_part_identity(&part, expected_device, expected_inode, expected_size)
    {
        quarantine(
            journal_root,
            &mut journal,
            format!("identity mismatch: {error:#}"),
        )?;
        return quarantined_receipt(
            context,
            journal_root,
            operation,
            mutation_operation_id,
            None,
            started_at_ms,
        );
    }
    let current_sha256 = hash_file(&part, None)?;
    let outcome = if current_sha256 == original_sha256 {
        journal.state = JournalState::Restored;
        crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired
    } else if current_sha256 == mutated_sha256 {
        let mut current = [0_u8; 1];
        ensure!(
            part.read_at(&mut current, offset)? == 1,
            "short restore read"
        );
        if current[0] != mutated_byte {
            quarantine(
                journal_root,
                &mut journal,
                "mutation byte does not match journal".to_string(),
            )?;
            return quarantined_receipt(
                context,
                journal_root,
                operation,
                mutation_operation_id,
                Some(current_sha256),
                started_at_ms,
            );
        }
        ensure!(
            part.write_at(&[original_byte], offset)? == 1,
            "short restore pwrite"
        );
        part.sync_all().context("fsync restored shard")?;
        validate_part_identity(&part, expected_device, expected_inode, expected_size)?;
        let restored_sha256 = hash_file(&part, None)?;
        if restored_sha256 != original_sha256 {
            quarantine(
                journal_root,
                &mut journal,
                "post-restore digest differs from the original".to_string(),
            )?;
            return quarantined_receipt(
                context,
                journal_root,
                operation,
                mutation_operation_id,
                Some(restored_sha256),
                started_at_ms,
            );
        }
        journal.state = JournalState::Restored;
        crate::fault::storage_recovery_runtime::RestoreOutcome::Restored
    } else {
        quarantine(
            journal_root,
            &mut journal,
            "shard digest matches neither original nor controlled mutation".to_string(),
        )?;
        return quarantined_receipt(
            context,
            journal_root,
            operation,
            mutation_operation_id,
            Some(current_sha256),
            started_at_ms,
        );
    };

    let response = OfflineShardRecoveryResponse {
        mutation_operation_id: mutation_operation_id.to_string(),
        outcome,
        observed_sha256: Some(original_sha256.to_string()),
    };
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, &journal)?;
    completed_receipt_with_id(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
        terminal_cleanup_operation_id(operation),
    )
}

fn verify_superseded(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let StorageRecoveryHostOperation::VerifySupersededShard {
        mutation_operation_id,
        post_inspection_operation_id,
    } = operation
    else {
        unreachable!("verify_superseded receives only VerifySupersededShard")
    };
    let mut mutation = load_journal(journal_root, mutation_operation_id)?;
    ensure!(
        mutation.schema_version == 1
            && mutation.operation_id == *mutation_operation_id
            && mutation.context_sha256 == context_sha256(context)?
            && mutation.scope_sha256 == context.scope_sha256
            && mutation.holder_identity
                == context.exclusive_access.kubernetes_lease.holder_identity
            && mutation.lease_uid == context.exclusive_access.kubernetes_lease.uid
            && mutation.lease_acquired_at_ms
                == context.exclusive_access.kubernetes_lease.acquired_at_ms
            && matches!(
                mutation.operation,
                StorageRecoveryHostOperation::MutateShard { .. }
            ),
        "superseded-shard source mutation is absent or not owned by this attempt"
    );
    if mutation.state == JournalState::VerifiedSuperseded {
        ensure!(
            mutation.terminal_post_inspection_operation_id.as_deref()
                == Some(post_inspection_operation_id.as_str()),
            "terminal superseded-shard journal belongs to another post inspection"
        );
        let original_sha256 =
            validate_terminal_repaired_shard(context, volume_root, journal_root, &mutation)?;
        let response = OfflineShardRecoveryResponse {
            mutation_operation_id: mutation_operation_id.clone(),
            outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::VerifiedSuperseded,
            observed_sha256: Some(original_sha256),
        };
        return completed_receipt_with_id(
            context,
            journal_root,
            operation.clone(),
            &response,
            started_at_ms,
            terminal_cleanup_operation_id(operation),
        );
    }
    ensure!(
        matches!(
            mutation.state,
            JournalState::Mutated | JournalState::Quarantined
        ),
        "superseded-shard source mutation is not recoverable"
    );
    let StorageRecoveryHostOperation::MutateShard {
        inspection_operation_id,
        part_number,
        ..
    } = &mutation.operation
    else {
        bail!("superseded-shard source journal is not a mutation")
    };
    let original_inspection = load_journal(journal_root, inspection_operation_id)?;
    let post_inspection = load_journal(journal_root, post_inspection_operation_id)?;
    ensure!(
        original_inspection.state == JournalState::Completed
            && post_inspection.state == JournalState::Completed
            && post_inspection.context_sha256 == context_sha256(context)?
            && post_inspection.scope_sha256 == context.scope_sha256
            && post_inspection.lease_uid == context.exclusive_access.kubernetes_lease.uid
            && post_inspection.lease_acquired_at_ms
                == context.exclusive_access.kubernetes_lease.acquired_at_ms
            && post_inspection.holder_identity
                == context.exclusive_access.kubernetes_lease.holder_identity,
        "superseded-shard post inspection is not a completed receipt for this context"
    );
    let original_body = required(
        &original_inspection.response_body,
        "original inspection response body",
    )?;
    let post_body = required(
        &post_inspection.response_body,
        "post inspection response body",
    )?;
    ensure!(
        original_inspection
            .response_sha256
            .as_deref()
            .is_some_and(|digest| digest == sha256_bytes(original_body.as_bytes()))
            && post_inspection
                .response_sha256
                .as_deref()
                .is_some_and(|digest| digest == sha256_bytes(post_body.as_bytes())),
        "superseded-shard inspections are not digest-bound"
    );
    let original: OfflineXl2InspectResponse =
        serde_json::from_str(original_body).context("decode original XL2 inspection")?;
    let post: OfflineXl2InspectResponse =
        serde_json::from_str(post_body).context("decode post-heal XL2 inspection")?;
    let StorageRecoveryHostOperation::InspectXlMeta {
        bucket: original_bucket,
        object_key: original_key,
        object_sha256: original_object_sha256,
        version_id: original_version,
        selected_part_number: original_part,
        expected_mount_device_id: original_device,
        expected_drive_uuid: original_drive,
        ..
    } = &original_inspection.operation
    else {
        bail!("superseded-shard source inspection has the wrong operation")
    };
    let StorageRecoveryHostOperation::InspectXlMeta {
        bucket: post_bucket,
        object_key: post_key,
        object_sha256: post_object_sha256,
        version_id: post_version,
        selected_part_number: post_part,
        expected_mount_device_id: post_device,
        expected_drive_uuid: post_drive,
        ..
    } = &post_inspection.operation
    else {
        bail!("superseded-shard post inspection has the wrong operation")
    };
    let old_inode = mutation
        .shard_inode
        .context("mutation journal lacks shard inode")?;
    let original_sha256 = required(&mutation.original_sha256, "mutation original digest")?;
    ensure!(
        original_bucket == post_bucket
            && original_key == post_key
            && original_object_sha256 == post_object_sha256
            && original_version == post_version
            && original_part == part_number
            && post_part == part_number
            && original_device == post_device
            && original_drive == post_drive
            && original.selected_part.part_number == *part_number
            && post.selected_part.part_number == *part_number
            && post.selected_part.shard_inode != old_inode
            && post.selected_part.original_sha256 == original_sha256,
        "post-heal inspection does not prove an exact repaired superseding shard"
    );
    let part = open_beneath(
        volume_root,
        &post.selected_part.relative_part_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    validate_part_identity(
        &part,
        &post.selected_part.shard_device_id,
        post.selected_part.shard_inode,
        post.selected_part.shard_size_bytes,
    )?;
    ensure!(
        hash_file(&part, None)? == post.selected_part.original_sha256,
        "superseding shard changed after the sealed post-heal inspection"
    );
    mutation.state = JournalState::VerifiedSuperseded;
    mutation.reason = None;
    mutation.terminal_post_inspection_operation_id = Some(post_inspection_operation_id.clone());
    mutation.updated_at_ms = now_ms()?;
    persist_journal(journal_root, &mutation)?;
    let response = OfflineShardRecoveryResponse {
        mutation_operation_id: mutation_operation_id.clone(),
        outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::VerifiedSuperseded,
        observed_sha256: Some(post.selected_part.original_sha256),
    };
    completed_receipt_with_id(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
        terminal_cleanup_operation_id(operation),
    )
}

fn validate_terminal_repaired_shard(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    mutation: &MutationJournal,
) -> Result<String> {
    let original_sha256 = required(&mutation.original_sha256, "mutation original digest")?;
    ensure!(
        original_sha256.len() == 64 && original_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "terminal mutation journal has an invalid original digest"
    );
    match mutation.state {
        JournalState::Restored => {
            let path = required(&mutation.relative_part_path, "journal shard path")?;
            let expected_device = required(&mutation.shard_device_id, "journal shard device")?;
            let expected_inode = mutation.shard_inode.context("journal lacks shard inode")?;
            let expected_size = mutation
                .shard_size_bytes
                .context("journal lacks shard size")?;
            let part = open_beneath(volume_root, path, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
            validate_part_identity(&part, expected_device, expected_inode, expected_size)?;
            ensure!(
                hash_file(&part, None)? == original_sha256,
                "terminal restored shard changed before cleanup receipt replay"
            );
        }
        JournalState::VerifiedSuperseded => {
            let StorageRecoveryHostOperation::MutateShard {
                inspection_operation_id,
                part_number,
                ..
            } = &mutation.operation
            else {
                bail!("terminal superseded-shard journal is not a mutation")
            };
            let post_operation_id = required(
                &mutation.terminal_post_inspection_operation_id,
                "terminal post inspection operationId",
            )?;
            let original = load_journal(journal_root, inspection_operation_id)?;
            let post = load_journal(journal_root, post_operation_id)?;
            ensure!(
                original.schema_version == 1
                    && original.state == JournalState::Completed
                    && original.context_sha256 == context_sha256(context)?
                    && original.scope_sha256 == context.scope_sha256
                    && original.lease_uid == context.exclusive_access.kubernetes_lease.uid
                    && original.lease_acquired_at_ms
                        == context.exclusive_access.kubernetes_lease.acquired_at_ms
                    && original.holder_identity
                        == context.exclusive_access.kubernetes_lease.holder_identity
                    && post.schema_version == 1
                    && post.state == JournalState::Completed
                    && post.context_sha256 == context_sha256(context)?
                    && post.scope_sha256 == context.scope_sha256
                    && post.lease_uid == context.exclusive_access.kubernetes_lease.uid
                    && post.lease_acquired_at_ms
                        == context.exclusive_access.kubernetes_lease.acquired_at_ms
                    && post.holder_identity
                        == context.exclusive_access.kubernetes_lease.holder_identity,
                "terminal post inspection belongs to another context"
            );
            let original_response_body =
                required(&original.response_body, "original inspection response body")?;
            let response_body = required(&post.response_body, "post inspection response body")?;
            ensure!(
                original.response_sha256.as_deref()
                    == Some(sha256_bytes(original_response_body.as_bytes()).as_str())
                    && post.response_sha256.as_deref()
                        == Some(sha256_bytes(response_body.as_bytes()).as_str()),
                "terminal post inspection response digest mismatch"
            );
            let original_response: OfflineXl2InspectResponse =
                serde_json::from_str(original_response_body)
                    .context("decode terminal original inspection response")?;
            let response: OfflineXl2InspectResponse = serde_json::from_str(response_body)
                .context("decode terminal post inspection response")?;
            let StorageRecoveryHostOperation::InspectXlMeta {
                bucket: original_bucket,
                object_key: original_key,
                object_sha256: original_object_sha256,
                version_id: original_version,
                selected_part_number: original_part,
                expected_mount_device_id: original_device,
                expected_drive_uuid: original_drive,
                ..
            } = &original.operation
            else {
                bail!("terminal source inspection has the wrong operation")
            };
            let StorageRecoveryHostOperation::InspectXlMeta {
                bucket: post_bucket,
                object_key: post_key,
                object_sha256: post_object_sha256,
                version_id: post_version,
                selected_part_number: post_part,
                expected_mount_device_id: post_device,
                expected_drive_uuid: post_drive,
                ..
            } = &post.operation
            else {
                bail!("terminal post inspection has the wrong operation")
            };
            ensure!(
                original_bucket == post_bucket
                    && original_key == post_key
                    && original_object_sha256 == post_object_sha256
                    && original_version == post_version
                    && original_part == part_number
                    && post_part == part_number
                    && original_device == post_device
                    && original_drive == post_drive
                    && original_response.selected_part.part_number == *part_number
                    && response.selected_part.part_number == *part_number
                    && mutation
                        .shard_inode
                        .is_some_and(|inode| response.selected_part.shard_inode != inode)
                    && response.selected_part.original_sha256 == original_sha256,
                "terminal post inspection does not prove the exact superseding shard"
            );
            let part = open_beneath(
                volume_root,
                &response.selected_part.relative_part_path,
                libc::O_RDONLY | libc::O_CLOEXEC,
                0,
            )?;
            validate_part_identity(
                &part,
                &response.selected_part.shard_device_id,
                response.selected_part.shard_inode,
                response.selected_part.shard_size_bytes,
            )?;
            ensure!(
                hash_file(&part, None)? == original_sha256,
                "terminal superseding shard changed before cleanup receipt replay"
            );
        }
        _ => bail!("mutation journal is not in a terminal repaired state"),
    }
    Ok(original_sha256.to_string())
}

#[allow(clippy::too_many_arguments)]
fn quarantined_receipt(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    mutation_operation_id: &str,
    observed_sha256: Option<String>,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let response = OfflineShardRecoveryResponse {
        mutation_operation_id: mutation_operation_id.to_string(),
        outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::Quarantined,
        observed_sha256,
    };
    completed_receipt(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
    )
}

fn quarantine(journal_root: &File, journal: &mut MutationJournal, reason: String) -> Result<()> {
    journal.state = JournalState::Quarantined;
    journal.reason = Some(reason);
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, journal)
}

fn persist_response(
    journal_root: &File,
    journal: &mut MutationJournal,
    response_body: &str,
) -> Result<u64> {
    journal.response_body = Some(response_body.to_string());
    journal.response_sha256 = Some(sha256_bytes(response_body.as_bytes()));
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, journal)?;
    Ok(journal.updated_at_ms)
}

fn completed_receipt(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: StorageRecoveryHostOperation,
    response: &impl Serialize,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    // Heartbeats only need their latest durable observation. Mutation and XL2
    // receipts retain distinct IDs because later operations refer to them.
    let operation_id = if matches!(
        operation,
        StorageRecoveryHostOperation::InspectHostGeneration
    ) {
        stable_operation_id(&format!("s3chaos-host-generation:{}", context.scope_sha256))
    } else {
        Uuid::new_v4().to_string()
    };
    completed_receipt_with_id(
        context,
        journal_root,
        operation,
        response,
        started_at_ms,
        operation_id,
    )
}

fn completed_receipt_with_id(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: StorageRecoveryHostOperation,
    response: &impl Serialize,
    started_at_ms: u64,
    operation_id: String,
) -> Result<StorageRecoveryOperationReceipt> {
    let persisted_at_ms = now_ms()?;
    let journal = MutationJournal {
        schema_version: 1,
        operation_id: operation_id.clone(),
        context_sha256: context_sha256(context)?,
        scope_sha256: context.scope_sha256.clone(),
        lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
        lease_acquired_at_ms: context.exclusive_access.kubernetes_lease.acquired_at_ms,
        holder_identity: context
            .exclusive_access
            .kubernetes_lease
            .holder_identity
            .clone(),
        operation: operation.clone(),
        state: JournalState::Completed,
        relative_part_path: None,
        shard_device_id: None,
        shard_inode: None,
        shard_size_bytes: None,
        byte_offset: None,
        original_byte: None,
        mutated_byte: None,
        original_sha256: None,
        mutated_sha256: None,
        reason: None,
        terminal_post_inspection_operation_id: None,
        response_body: Some(serde_json::to_string(response)?),
        response_sha256: None,
        started_at_ms,
        updated_at_ms: persisted_at_ms,
    };
    let mut journal = journal;
    let response_body = journal
        .response_body
        .clone()
        .context("completed response")?;
    journal.response_sha256 = Some(sha256_bytes(response_body.as_bytes()));
    persist_journal(journal_root, &journal)?;
    receipt(
        context,
        operation,
        operation_id,
        response_body,
        started_at_ms,
        persisted_at_ms,
    )
}

fn terminal_cleanup_operation_id(operation: &StorageRecoveryHostOperation) -> String {
    let identity = match operation {
        StorageRecoveryHostOperation::RestoreShard {
            mutation_operation_id,
        } => format!("restore:{mutation_operation_id}"),
        StorageRecoveryHostOperation::VerifySupersededShard {
            mutation_operation_id,
            post_inspection_operation_id,
        } => format!("verify:{mutation_operation_id}:{post_inspection_operation_id}"),
        _ => unreachable!("terminal cleanup operation id requires a cleanup operation"),
    };
    stable_operation_id(&format!("s3chaos-bitrot-cleanup:{identity}"))
}

fn stable_operation_id(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn receipt(
    context: &OwnedStorageContext,
    operation: StorageRecoveryHostOperation,
    operation_id: String,
    response_body: String,
    started_at_ms: u64,
    journal_persisted_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let completed_at_ms = now_ms()?;
    let receipt = StorageRecoveryOperationReceipt {
        operation_id,
        operation,
        context_sha256: context_sha256(context)?,
        response_sha256: sha256_bytes(response_body.as_bytes()),
        response_body,
        started_at_ms,
        completed_at_ms,
        journal_persisted_at_ms,
        journal_fsync_succeeded: true,
    };
    receipt.validate_for(context, &receipt.operation)?;
    Ok(receipt)
}

fn validate_part_identity(
    file: &File,
    expected_device: &str,
    expected_inode: u64,
    expected_size: u64,
) -> Result<()> {
    let metadata = file.metadata().context("fstat contained shard")?;
    ensure!(metadata.is_file(), "contained shard is not a regular file");
    ensure!(
        metadata.nlink() == 1,
        "contained shard has multiple hard links"
    );
    ensure!(
        device_id(&metadata) == expected_device
            && metadata.ino() == expected_inode
            && metadata.len() == expected_size,
        "contained shard device/inode/size differs from the mapping receipt"
    );
    Ok(())
}

fn hash_file(file: &File, substitute: Option<(u64, u8)>) -> Result<String> {
    let mut reader = file.try_clone().context("clone shard fd for hashing")?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if let Some((target, byte)) = substitute
            && target >= offset
            && target < offset + count as u64
        {
            buffer[usize::try_from(target - offset)?] = byte;
        }
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn open_directory(path: &Path, label: &str) -> Result<File> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("{label} contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("open {label}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_beneath(root: &File, relative: &str, flags: i32, mode: u32) -> Result<File> {
    ensure!(
        !relative.is_empty()
            && !relative.starts_with('/')
            && relative
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "storage helper path is not normalized and relative"
    );
    let path = CString::new(relative).context("storage helper path contains NUL")?;
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve: STORAGE_RESOLVE_FLAGS,
    };
    let fd = openat2_fd(root.as_raw_fd(), &path, &how);
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open contained storage path {relative:?}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn ensure_absent_beneath(root: &File, relative: &str) -> Result<()> {
    ensure!(
        !relative.is_empty()
            && !relative.starts_with('/')
            && relative
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "storage helper absence path is not normalized and relative"
    );
    let path = CString::new(relative).context("storage helper absence path contains NUL")?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: STORAGE_RESOLVE_FLAGS,
    };
    let fd = openat2_fd(root.as_raw_fd(), &path, &how);
    if fd >= 0 {
        drop(unsafe { File::from_raw_fd(fd) });
        bail!("run-owned stale orphan remains present after cleanup")
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(libc::ENOENT),
        "cannot prove stale orphan absence: {error}"
    );
    Ok(())
}

fn acquire_flock(file: &File) -> Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("acquire exclusive storage helper flock");
    }
    Ok(())
}

fn persist_journal(root: &File, journal: &MutationJournal) -> Result<()> {
    let final_name = journal_name(&journal.operation_id)?;
    let temporary_name = format!(".{final_name}.{}.tmp", std::process::id());
    let mut temporary = open_beneath(
        root,
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )?;
    let old = CString::new(temporary_name.clone())?;
    let write_result = (|| -> Result<()> {
        let body = serde_json::to_vec(journal)?;
        temporary.write_all(&body)?;
        temporary
            .sync_all()
            .context("fsync storage mutation journal")
    })();
    drop(temporary);
    if let Err(error) = write_result {
        let _ = unsafe { libc::unlinkat(root.as_raw_fd(), old.as_ptr(), 0) };
        return Err(error).context("persist storage mutation journal temporary file");
    }
    let new = CString::new(final_name.clone())?;
    let result = unsafe {
        libc::renameat(
            root.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
        )
    };
    if result != 0 {
        let _ = unsafe { libc::unlinkat(root.as_raw_fd(), old.as_ptr(), 0) };
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("publish storage journal {final_name}"));
    }
    root.sync_all().context("fsync storage journal directory")
}

fn load_journal(root: &File, operation_id: &str) -> Result<MutationJournal> {
    let name = journal_name(operation_id)?;
    let file = open_beneath(root, &name, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    serde_json::from_slice(&read_limited(&file, MAX_JOURNAL_BYTES, "mutation journal")?)
        .context("decode mutation journal")
}

fn ensure_no_unresolved_journals(journal_root: &File, context: &OwnedStorageContext) -> Result<()> {
    let current_context_sha256 = context_sha256(context)?;
    let current_holder = &context.exclusive_access.kubernetes_lease.holder_identity;
    let directory = format!("/proc/self/fd/{}", journal_root.as_raw_fd());
    for entry in std::fs::read_dir(&directory)
        .with_context(|| format!("scan pre-opened storage journal directory {directory}"))?
    {
        let entry = entry.context("read storage journal directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("storage journal has a non-UTF-8 filename"))?;
        let Some(operation_id) = name
            .strip_prefix("mutation-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        let journal = load_journal(journal_root, operation_id)
            .with_context(|| format!("validate existing storage journal {name}"))?;
        if journal.scope_sha256 != context.scope_sha256 {
            continue;
        }
        ensure!(
            journal.schema_version == 1,
            "existing storage journal has an unsupported schema"
        );
        match journal.state {
            JournalState::Completed | JournalState::Restored | JournalState::VerifiedSuperseded => {
                continue;
            }
            JournalState::Prepared | JournalState::Mutated
                if journal.lease_uid == context.exclusive_access.kubernetes_lease.uid
                    && journal.lease_acquired_at_ms
                        == context.exclusive_access.kubernetes_lease.acquired_at_ms
                    && journal.context_sha256 == current_context_sha256
                    && journal.holder_identity == *current_holder => {}
            JournalState::Prepared | JournalState::Mutated => {
                bail!(
                    "unresolved storage mutation does not belong to the current Lease and holder; explicit recovery is required"
                )
            }
            JournalState::Quarantined => {
                bail!(
                    "quarantined storage mutation requires explicit repair acknowledgement before a new session"
                )
            }
        }
    }
    Ok(())
}

fn journal_name(operation_id: &str) -> Result<String> {
    let id = Uuid::parse_str(operation_id).context("journal operation id is not a UUID")?;
    Ok(format!("mutation-{id}.json"))
}

fn read_limited(file: &File, limit: usize, label: &str) -> Result<Vec<u8>> {
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(metadata.is_file(), "{label} is not a regular file");
    let length = usize::try_from(metadata.len()).context("file length overflow")?;
    ensure!(
        length > 0 && length <= limit,
        "{label} is empty or oversized"
    );
    let mut reader = file.try_clone()?;
    let mut body = Vec::with_capacity(length);
    Read::by_ref(&mut reader)
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() == length && body.len() <= limit,
        "{label} changed while it was read"
    );
    Ok(body)
}

fn required<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str> {
    value
        .as_deref()
        .with_context(|| format!("{label} is absent"))
}

fn openat2_fd(dirfd: i32, path: &CString, how: &OpenHow) -> i32 {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                how,
                size_of::<OpenHow>(),
            ) as i32
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dirfd, path, how);
        // RESOLVE_BENEATH is Linux-only. Fail closed instead of opening with
        // a weaker check. The release-gate artifact command does not need it.
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = libc::ENOSYS;
        }
        -1
    }
}

fn device_id(metadata: &std::fs::Metadata) -> String {
    let device = metadata.dev();
    #[cfg(target_os = "linux")]
    {
        let major = libc::major(device);
        let minor = libc::minor(device);
        format!("{major}:{minor}")
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("{device}")
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("system timestamp exceeds u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::storage_recovery_runtime::*;
    use crate::fault::xl2_inspector::{
        test_fixture as xl2_fixture, test_inline_fixture as xl2_inline_fixture,
    };
    use std::{fs, os::unix::fs::symlink};
    use tempfile::TempDir;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn execute(
        invocation: StorageHelperInvocation,
        roots: &StorageHelperRoots,
    ) -> Result<StorageRecoveryOperationReceipt> {
        StorageHelperSession::begin(invocation.context.clone(), roots)?.execute(invocation)
    }

    fn test_roots() -> (TempDir, StorageHelperRoots) {
        let temporary = tempfile::tempdir().expect("temporary roots");
        for name in ["volume", "journal", "lock"] {
            fs::create_dir(temporary.path().join(name)).expect("helper root");
        }
        let roots = StorageHelperRoots {
            volume: temporary.path().join("volume"),
            journal: temporary.path().join("journal"),
            lock: temporary.path().join("lock"),
            host_proc: temporary.path().join("host-proc"),
            host_dev: temporary.path().join("host-dev"),
            trust_context_host_generation: true,
        };
        (temporary, roots)
    }

    fn context_for(roots: &StorageHelperRoots) -> OwnedStorageContext {
        let volume_metadata = fs::metadata(&roots.volume).expect("volume metadata");
        let device = device_id(&volume_metadata);
        let mut context = OwnedStorageContext {
            identity: crate::fault::storage_recovery::StorageRecoveryArtifactIdentity {
                run_id: "run-1".to_string(),
                scenario: "on-disk-bitrot".to_string(),
                case_name: "automatic-scanner".to_string(),
                bucket: "bucket-1".to_string(),
            },
            case: crate::fault::storage_recovery::StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            attempt_id: "attempt-1".to_string(),
            cluster_context: "kind-s3chaos".to_string(),
            tenant_uid: "tenant-uid-1".to_string(),
            scope_sha256: String::new(),
            volume: crate::fault::storage_recovery::StorageVolumeIdentity {
                target_proof_sha256: HASH.to_string(),
                host_storage_proof_sha256: HASH.to_string(),
                rustfs_deployment_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string(),
                namespace: "rustfs-system".to_string(),
                tenant: "tenant-1".to_string(),
                pod: "rustfs-0".to_string(),
                pod_uid: "pod-uid-1".to_string(),
                rustfs_container_id: "containerd://container-1".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: "data-rustfs-0".to_string(),
                persistent_volume_claim_uid: "pvc-uid-1".to_string(),
                persistent_volume: "pv-1".to_string(),
                persistent_volume_uid: "pv-uid-1".to_string(),
                node: "node-1".to_string(),
                node_uid: "node-uid-1".to_string(),
                storage_class: "local".to_string(),
                local_volume_path: "/var/lib/rustfs-1".to_string(),
                mount_path: "/data".to_string(),
                canonical_device: "/dev/mapper/rustfs-1".to_string(),
                target_mount_namespace_id: "mnt:[1]".to_string(),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
                pool_index: 0,
                set_index: 0,
                observed_at_ms: now_ms().expect("now") - 100,
            },
            resource_versions: KubernetesResourceVersions {
                tenant: "10".to_string(),
                pod: "11".to_string(),
                persistent_volume_claim: "12".to_string(),
                persistent_volume: "13".to_string(),
                node: "14".to_string(),
                helper_pod: "15".to_string(),
            },
            host_generation: HostGenerationIdentity {
                mount_id: "mount-1".to_string(),
                mount_namespace_id: "mnt:[1]".to_string(),
                device_major_minor: device,
                device_mapper_uuid: Some("dm-uuid-1".to_string()),
                device_mapper_table_sha256: Some(HASH.to_string()),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: KubernetesLeaseProof {
                    name: String::new(),
                    uid: "lease-uid-1".to_string(),
                    resource_version: "20".to_string(),
                    holder_identity: "run-1/attempt-1".to_string(),
                    scope_sha256: String::new(),
                    acquired_at_ms: now_ms().expect("now") - 100,
                    renew_at_ms: now_ms().expect("now") - 50,
                    expires_at_ms: now_ms().expect("now") + 60_000,
                },
                host_flock: HostFlockProof {
                    node: "node-1".to_string(),
                    node_uid: "node-uid-1".to_string(),
                    path: String::new(),
                    device_id: String::new(),
                    inode: 0,
                    scope_sha256: String::new(),
                    acquired_at_ms: now_ms().expect("now") - 25,
                },
            },
            helper_pod_name: "s3chaos-storage-helper".to_string(),
            helper_pod_uid: "helper-uid-1".to_string(),
            observed_at_ms: now_ms().expect("now"),
        };
        let scope = storage_scope_sha256(&context);
        let lock_path = roots.lock.join(format!("storage-{scope}.lock"));
        File::create(&lock_path).expect("lock file");
        let lock_metadata = fs::metadata(lock_path).expect("lock metadata");
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope}.lock");
        context.exclusive_access.host_flock.device_id = device_id(&lock_metadata);
        context.exclusive_access.host_flock.inode = lock_metadata.ino();
        context.exclusive_access.host_flock.scope_sha256 = scope;
        context
    }

    fn next_lease_generation(mut context: OwnedStorageContext) -> OwnedStorageContext {
        let observed_at_ms = now_ms().expect("now");
        context.identity.run_id = "run-2".to_string();
        context.attempt_id = "attempt-2".to_string();
        context.exclusive_access.kubernetes_lease.uid = "lease-uid-2".to_string();
        context.exclusive_access.kubernetes_lease.resource_version = "21".to_string();
        context.exclusive_access.kubernetes_lease.holder_identity = "run-2/attempt-2".to_string();
        context.exclusive_access.kubernetes_lease.acquired_at_ms = observed_at_ms - 10;
        context.exclusive_access.kubernetes_lease.renew_at_ms = observed_at_ms - 5;
        context.exclusive_access.kubernetes_lease.expires_at_ms = observed_at_ms + 60_000;
        context.exclusive_access.host_flock.acquired_at_ms = observed_at_ms - 2;
        context.observed_at_ms = observed_at_ms;
        context
    }

    fn renew_same_lease(mut context: OwnedStorageContext) -> OwnedStorageContext {
        context.exclusive_access.kubernetes_lease.resource_version = "21".to_string();
        context.exclusive_access.kubernetes_lease.renew_at_ms += 1;
        context.exclusive_access.kubernetes_lease.expires_at_ms += 60_000;
        context.observed_at_ms += 1;
        context.volume.observed_at_ms = context.observed_at_ms;
        context
    }

    fn mutation(
        context: &OwnedStorageContext,
        roots: &StorageHelperRoots,
        path: &str,
    ) -> StorageRecoveryHostOperation {
        let metadata = fs::metadata(path).expect("part metadata");
        let body = fs::read(path).expect("part body");
        let relative_part_path = "bucket/object/data-dir/part.1".to_string();
        let inspection = completed_receipt(
            context,
            &open_directory(&roots.journal, "journal root").expect("journal root"),
            StorageRecoveryHostOperation::InspectXlMeta {
                object_directory: "bucket/object".to_string(),
                bucket: "bucket-1".to_string(),
                object_key: "object".to_string(),
                object_sha256: HASH.to_string(),
                version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                selected_part_number: 1,
                expected_mount_device_id: context.host_generation.device_major_minor.clone(),
                expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
            },
            &OfflineXl2InspectResponse {
                mount_device_id: context.host_generation.device_major_minor.clone(),
                drive_uuid: context.volume.rustfs_drive_uuid.clone(),
                format_json_sha256: HASH.to_string(),
                xl_meta_sha256: HASH.to_string(),
                layout: crate::fault::xl2_inspector::Xl2ObjectVersionLayout {
                    inspector_revision: crate::fault::xl2_inspector::OFFLINE_XL2_INSPECTOR_REVISION
                        .to_string(),
                    profile: crate::fault::xl2_inspector::Xl2FormatProfile::LATEST_RUSTFS,
                    version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                    data_directory: "data-dir".to_string(),
                    erasure_data_shards: 1,
                    erasure_parity_shards: 1,
                    erasure_index: 1,
                    part_numbers: vec![1],
                    part_sizes: vec![metadata.len()],
                    relative_part_paths: vec![relative_part_path.clone()],
                },
                selected_part: OfflineInspectedShard {
                    part_number: 1,
                    relative_part_path,
                    shard_device_id: context.host_generation.device_major_minor.clone(),
                    shard_inode: metadata.ino(),
                    shard_size_bytes: metadata.len(),
                    original_sha256: sha256_bytes(&body),
                },
            },
            now_ms().expect("now"),
        )
        .expect("sealed inspection receipt");
        StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: inspection.operation_id,
            part_number: 1,
            byte_offset: 1,
        }
    }

    fn stale_request(operation: StaleOfflineHelperOperation) -> StaleOfflineHelperRequest {
        StaleOfflineHelperRequest {
            run_id: "run-stale-1".to_string(),
            scenario: "stale-disk-return-detect".to_string(),
            volume_root: "/host/var/lib/rustfs-stale".to_string(),
            deployment_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string(),
            drive_uuid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
            filesystem_uuid: "fs-stale-1".to_string(),
            bucket: "bucket-stale-1".to_string(),
            operation,
        }
    }

    #[test]
    fn host_generation_heartbeats_reuse_one_durable_journal() {
        let (_directory, roots) = test_roots();
        let context = context_for(&roots);
        let journal = open_directory(&roots.journal, "journal root").expect("journal");
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let observed_at = now_ms().expect("clock");
            let receipt = completed_receipt(
                &context,
                &journal,
                StorageRecoveryHostOperation::InspectHostGeneration,
                &context.host_generation,
                observed_at,
            )
            .expect("heartbeat");
            receipt
                .validate_for(&context, &receipt.operation)
                .expect("durable receipt");
            ids.insert(receipt.operation_id);
        }
        assert_eq!(ids.len(), 1);
        assert_eq!(
            fs::read_dir(&roots.journal).expect("journal files").count(),
            1
        );
        let persisted =
            load_journal(&journal, ids.first().expect("operation id")).expect("latest journal");
        assert_eq!(persisted.state, JournalState::Completed);
    }

    #[test]
    fn stale_orphan_injection_is_exclusive_and_removal_is_owner_bound() {
        let (_temporary, roots) = test_roots();
        let object = roots.volume.join("bucket-stale-1/object-1");
        fs::create_dir_all(&object).expect("stale object directory");
        fs::write(object.join("xl.meta"), b"sealed metadata placeholder")
            .expect("stale object metadata");
        let root = open_directory(&roots.volume, "stale test volume").expect("open volume");
        let version_id = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let request = stale_request(StaleOfflineHelperOperation::InjectOrphan {
            object_key: "object-1".to_string(),
            version_id: version_id.to_string(),
        });
        let receipt = match inject_stale_orphan(&request, &root, "object-1", version_id)
            .expect("inject run-owned orphan")
        {
            StaleOfflineHelperResponse::OrphanInjected { receipt } => receipt,
            response => panic!("unexpected helper response: {response:?}"),
        };
        assert_eq!(receipt.run_id, request.run_id);
        assert_eq!(receipt.drive_uuid, request.drive_uuid);
        assert!(
            roots.volume.join(&receipt.relative_part_path).is_file(),
            "injection must publish the exact receipt-bound part"
        );
        assert!(
            inject_stale_orphan(&request, &root, "object-1", version_id).is_err(),
            "the orphan UUID is an exclusive identity"
        );

        let mut foreign = receipt.clone();
        foreign.run_id = "another-run".to_string();
        assert!(remove_stale_orphan(&request, &root, &foreign).is_err());
        assert!(roots.volume.join(&receipt.relative_part_path).is_file());
        let removed =
            remove_stale_orphan(&request, &root, &receipt).expect("remove exact run-owned orphan");
        assert!(matches!(
            removed,
            StaleOfflineHelperResponse::OrphanRemoved { ref fragment_id, .. }
                if fragment_id == &receipt.fragment_id
        ));
        ensure_absent_beneath(&root, &receipt.relative_part_path)
            .expect("removed orphan is absent");
        assert!(remove_stale_orphan(&request, &root, &receipt).is_err());
    }

    #[test]
    fn inspection_seals_the_volume_relative_object_shard_path() {
        const VERSION_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
        const DATA_DIRECTORY: &str = "fedcba98-7654-3210-fedc-ba9876543210";

        let (_temporary, roots) = test_roots();
        let context = context_for(&roots);
        let object_directory = "bucket-1/object";
        let relative_part_path = format!("{object_directory}/{DATA_DIRECTORY}/part.1");
        let part_path = roots.volume.join(&relative_part_path);
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        let original = vec![0x5a; 1024];
        fs::write(&part_path, &original).expect("part");
        fs::write(
            roots.volume.join(object_directory).join("xl.meta"),
            crate::fault::xl2_inspector::test_fixture(VERSION_ID, Some(DATA_DIRECTORY), &[1]),
        )
        .expect("xl.meta");
        fs::create_dir_all(roots.volume.join(".rustfs.sys")).expect("system directory");
        fs::write(
            roots.volume.join(FORMAT_JSON_PATH),
            serde_json::to_vec(&serde_json::json!({
                "version": "1",
                "format": "xl-single",
                "id": context.volume.rustfs_deployment_id,
                "xl": {
                    "version": "3",
                    "this": context.volume.rustfs_drive_uuid,
                    "sets": [[context.volume.rustfs_drive_uuid]],
                    "distributionAlgo": "SIPMOD+PARITY"
                }
            }))
            .expect("format.json body"),
        )
        .expect("format.json");

        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let inspection = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::InspectXlMeta {
                    object_directory: object_directory.to_string(),
                    bucket: context.identity.bucket.clone(),
                    object_key: "object".to_string(),
                    object_sha256: HASH.to_string(),
                    version_id: VERSION_ID.to_string(),
                    selected_part_number: 1,
                    expected_mount_device_id: context.host_generation.device_major_minor.clone(),
                    expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
                },
            })
            .expect("inspect real shard hierarchy");
        let inspected: OfflineXl2InspectResponse =
            serde_json::from_str(&inspection.response_body).expect("inspection response");
        assert_eq!(
            inspected.layout.relative_part_paths,
            std::slice::from_ref(&relative_part_path)
        );
        assert_eq!(
            inspected.selected_part.relative_part_path,
            relative_part_path
        );

        let mutation = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::MutateShard {
                    inspection_operation_id: inspection.operation_id,
                    part_number: 1,
                    byte_offset: 1,
                },
            })
            .expect("mutate inspected shard");
        assert_ne!(fs::read(&part_path).expect("mutated part"), original);
        let restored = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutation.operation_id,
                },
            })
            .expect("restore inspected shard");
        session
            .finish(
                &context,
                &StorageRecoveryCleanupProof::BitrotRestored {
                    restore_receipt: Box::new(restored),
                },
            )
            .expect("finish session");
        assert_eq!(fs::read(part_path).expect("restored part"), original);
    }

    #[test]
    fn stale_inventory_traversal_surfaces_unlisted_versions_and_orphans() {
        let (_temporary, roots) = test_roots();
        let expected_version = "11111111-1111-1111-1111-111111111111";
        let expected_data = "22222222-2222-2222-2222-222222222222";
        let extra_version = "33333333-3333-3333-3333-333333333333";
        let extra_data = "44444444-4444-4444-4444-444444444444";
        for (object, version, data, body) in [
            (
                "fault-test/run-stale-1/expected",
                expected_version,
                expected_data,
                b"expected".as_slice(),
            ),
            (
                "fault-test/run-stale-1/unlisted",
                extra_version,
                extra_data,
                b"unlisted".as_slice(),
            ),
        ] {
            let directory = roots.volume.join("bucket-stale-1").join(object).join(data);
            fs::create_dir_all(&directory).expect("XL2 data directory");
            fs::write(directory.join("part.1"), body).expect("XL2 part");
            fs::write(
                directory
                    .parent()
                    .expect("object directory")
                    .join("xl.meta"),
                xl2_fixture(version, Some(data), &[1]),
            )
            .expect("XL2 metadata");
        }
        let inline_version = "77777777-7777-7777-7777-777777777777";
        let inline_object = roots
            .volume
            .join("bucket-stale-1/fault-test/run-stale-1/inline");
        fs::create_dir_all(&inline_object).expect("inline object directory");
        fs::write(
            inline_object.join("xl.meta"),
            xl2_inline_fixture(inline_version),
        )
        .expect("inline XL2 metadata");
        let root = open_directory(&roots.volume, "stale test volume").expect("open volume");
        let request = stale_request(StaleOfflineHelperOperation::InjectOrphan {
            object_key: "fault-test/run-stale-1/expected".to_string(),
            version_id: "55555555-5555-5555-5555-555555555555".to_string(),
        });
        let orphan = match inject_stale_orphan(
            &request,
            &root,
            "fault-test/run-stale-1/expected",
            "55555555-5555-5555-5555-555555555555",
        )
        .expect("inject owned orphan")
        {
            StaleOfflineHelperResponse::OrphanInjected { receipt } => receipt,
            response => panic!("unexpected helper response: {response:?}"),
        };
        let extra_orphan = roots.volume.join(
            "bucket-stale-1/fault-test/run-stale-1/expected/66666666-6666-6666-6666-666666666666",
        );
        fs::create_dir(&extra_orphan).expect("extra orphan directory");
        fs::write(extra_orphan.join("part.1"), b"unexpected orphan").expect("extra orphan part");

        let expected_versions = [
            StaleOfflineExpectedVersion {
                operation_id: "put-expected".to_string(),
                object_key: "fault-test/run-stale-1/expected".to_string(),
                version_id: expected_version.to_string(),
                object_sha256: HASH.to_string(),
            },
            StaleOfflineExpectedVersion {
                operation_id: "put-inline".to_string(),
                object_key: "fault-test/run-stale-1/inline".to_string(),
                version_id: inline_version.to_string(),
                object_sha256: HASH.to_string(),
            },
        ];
        let response = inventory_stale_scope(
            &request,
            &root,
            "99999999-9999-9999-9999-999999999999",
            &expected_versions,
            &orphan,
            true,
        )
        .expect("exhaustive stale inventory");
        let StaleOfflineHelperResponse::Inventory { response, .. } = response else {
            panic!("unexpected inventory response")
        };
        assert!(response.exhausted);
        assert_eq!(response.entries.len(), 5);
        assert!(response.entries.iter().any(|entry| {
            entry.object_key == "fault-test/run-stale-1/inline"
                && entry.version_id == inline_version
                && entry.reference_state == FragmentReferenceState::ReferencedVersion
        }));
        assert!(response.entries.iter().any(|entry| {
            entry.object_key == "fault-test/run-stale-1/unlisted"
                && entry.version_id == extra_version
                && entry.reference_state == FragmentReferenceState::Unclassified
        }));
        assert!(response.entries.iter().any(|entry| {
            entry.version_id == "66666666-6666-6666-6666-666666666666"
                && entry.reference_state == FragmentReferenceState::Unclassified
        }));
    }

    #[test]
    fn controlled_mutation_is_durable_and_compare_restores() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        let other_part_path = roots.volume.join("bucket/object/data-dir/part.2");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        fs::write(&other_part_path, b"other shard payload").expect("other part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let mutated = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation,
            })
            .expect("mutate shard");
        let journal_root = open_directory(&roots.journal, "journal root").expect("journal root");
        let mutation_journal =
            load_journal(&journal_root, &mutated.operation_id).expect("mutation journal");
        assert_eq!(
            mutation_journal.response_body.as_deref(),
            Some(mutated.response_body.as_str())
        );
        assert_eq!(
            mutation_journal.response_sha256.as_deref(),
            Some(mutated.response_sha256.as_str())
        );
        assert_ne!(
            fs::read(&part_path).expect("mutated part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(&other_part_path).expect("other part"),
            b"other shard payload",
            "a receipt-derived mutation must not touch another part on the same volume"
        );

        let restored = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutated.operation_id,
                },
            })
            .expect("restore shard");
        let restore_journal =
            load_journal(&journal_root, &restored.operation_id).expect("restore receipt journal");
        assert_eq!(restore_journal.operation, restored.operation);
        assert_eq!(
            restore_journal.response_sha256.as_deref(),
            Some(restored.response_sha256.as_str())
        );
        let cleanup = StorageRecoveryCleanupProof::BitrotRestored {
            restore_receipt: Box::new(restored),
        };
        session.finish(&context, &cleanup).expect("finish session");
        assert_eq!(
            fs::read(part_path).expect("restored part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(other_part_path).expect("other part"),
            b"other shard payload"
        );
    }

    #[test]
    fn same_lease_renewal_preserves_unresolved_journal_and_restore_ownership() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        let original = b"original shard payload";
        fs::write(&part_path, original).expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let mutated = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation,
            })
            .expect("mutate shard");
        drop(session);

        let renewed = renew_same_lease(context);
        mutated
            .validate_for(&renewed, &mutated.operation)
            .expect("mutation receipt must survive Lease renewal");
        let mut renewed_session = StorageHelperSession::begin(renewed.clone(), &roots)
            .expect("same Lease renewal must retain unresolved journal ownership");
        let restored = renewed_session
            .execute(StorageHelperInvocation {
                context: renewed.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutated.operation_id,
                },
            })
            .expect("restore shard after Lease renewal");
        renewed_session
            .finish(
                &renewed,
                &StorageRecoveryCleanupProof::BitrotRestored {
                    restore_receipt: Box::new(restored),
                },
            )
            .expect("finish renewed session");
        assert_eq!(fs::read(part_path).expect("restored part"), original);
    }

    #[test]
    fn prejournal_mutation_rejection_allows_abort_and_has_no_journal() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mut changed = fs::read(&part_path).expect("part body");
        changed[0] ^= CONTROLLED_SHARD_XOR_MASK;
        fs::write(&part_path, &changed).expect("change shard before mutation");
        let operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let error = session
            .execute_mutation_with_id(
                StorageHelperInvocation {
                    context: context.clone(),
                    operation,
                },
                operation_id,
            )
            .expect_err("changed shard must reject before journal creation");
        assert!(error.to_string().contains("hash drifted before mutation"));
        assert!(
            !session
                .mutation_journal_exists(operation_id)
                .expect("journal absence")
        );
        session
            .finish(
                &context,
                &StorageRecoveryCleanupProof::AbortedBeforeMutation {
                    observed_at_ms: now_ms().expect("now"),
                },
            )
            .expect("pre-journal rejection releases helper ownership");
        assert_eq!(fs::read(part_path).expect("part body"), changed);
    }

    #[test]
    fn fresh_volume_cleanup_requires_committed_physical_replacement() {
        let (_temporary, roots) = test_roots();
        let mut context = context_for(&roots);
        context.identity.scenario = "fresh-volume-replacement".to_string();
        context.identity.case_name = "fresh-volume-replacement-automatic-replacement".to_string();
        context.case =
            crate::fault::storage_recovery::StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement;
        let scope = storage_scope_sha256(&context);
        let lock_path = roots.lock.join(format!("storage-{scope}.lock"));
        File::create(&lock_path).expect("fresh-volume lock file");
        let lock_metadata = fs::metadata(lock_path).expect("fresh-volume lock metadata");
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope}.lock");
        context.exclusive_access.host_flock.device_id = device_id(&lock_metadata);
        context.exclusive_access.host_flock.inode = lock_metadata.ino();
        context.exclusive_access.host_flock.scope_sha256 = scope;
        let proof = StorageRecoveryCleanupProof::AbortedBeforeMutation {
            observed_at_ms: context
                .exclusive_access
                .kubernetes_lease
                .acquired_at_ms
                .saturating_add(1),
        };
        StorageHelperSession::begin(context.clone(), &roots)
            .expect("read-only session")
            .finish(&context, &proof)
            .expect("read-only attempt may abort");

        let mut session =
            StorageHelperSession::begin(context.clone(), &roots).expect("fresh mutating session");
        let prepared = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::PrepareFreshVolume {
                    replacement_persistent_volume: "replacement-pv".to_string(),
                    replacement_persistent_volume_claim: context
                        .volume
                        .persistent_volume_claim
                        .clone(),
                },
            })
            .expect("begin fresh-volume mutation");
        let error = session
            .finish(&context, &proof)
            .expect_err("mutating session must reject pre-mutation abort");
        assert!(
            error.to_string().contains("after mutation began"),
            "{error:#}"
        );

        let mut replacement = context.volume.clone();
        replacement.persistent_volume = "replacement-pv".to_string();
        replacement.persistent_volume_uid = "replacement-pv-uid".to_string();
        replacement.persistent_volume_claim_uid = "replacement-pvc-uid".to_string();
        replacement.canonical_device = "/dev/replacement".to_string();
        replacement.filesystem_uuid = "replacement-fs".to_string();
        replacement.observed_at_ms = prepared
            .completed_at_ms
            .max(context.volume.observed_at_ms + 1);
        let committed = StorageRecoveryCleanupProof::FreshVolumeCommitted {
            observed_at_ms: replacement.observed_at_ms,
            prepare_receipt: Box::new(prepared),
            replacement_volume: Box::new(replacement.clone()),
            old_device_absence_sha256: "a".repeat(64),
        };
        session
            .finish(&context, &committed)
            .expect("physical replacement may retain the logical slot UUID");
        for invalid in ["filesystem", "pvc", "node", "slot"] {
            let mut forged = committed.clone();
            let StorageRecoveryCleanupProof::FreshVolumeCommitted {
                replacement_volume, ..
            } = &mut forged
            else {
                unreachable!();
            };
            match invalid {
                "filesystem" => {
                    replacement_volume.filesystem_uuid = context.volume.filesystem_uuid.clone()
                }
                "pvc" => {
                    replacement_volume.persistent_volume_claim_uid =
                        context.volume.persistent_volume_claim_uid.clone()
                }
                "node" => replacement_volume.node_uid = "foreign-node".to_string(),
                "slot" => replacement_volume.set_index += 1,
                _ => unreachable!(),
            }
            assert!(
                session.finish(&context, &forged).is_err(),
                "invalid {invalid} cleanup proof"
            );
        }
    }

    #[test]
    fn mutation_requires_the_exact_sealed_inspection_and_part() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        let other_part_path = roots.volume.join("bucket/object/data-dir/part.2");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        fs::write(&other_part_path, b"other shard payload").expect("other part");
        let context = context_for(&roots);

        let mut wrong_inspection =
            mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id,
            ..
        } = &mut wrong_inspection
        else {
            unreachable!("test operation is a mutation")
        };
        *inspection_operation_id = Uuid::new_v4().to_string();
        assert!(
            execute(
                StorageHelperInvocation {
                    context: context.clone(),
                    operation: wrong_inspection,
                },
                &roots,
            )
            .is_err(),
            "an unknown inspection id must fail closed"
        );

        let mut switched_part = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard { part_number, .. } = &mut switched_part
        else {
            unreachable!("test operation is a mutation")
        };
        *part_number = 2;
        assert!(
            execute(
                StorageHelperInvocation {
                    context,
                    operation: switched_part,
                },
                &roots,
            )
            .is_err(),
            "a controller-selected part different from the sealed inspection must fail closed"
        );
        assert_eq!(
            fs::read(part_path).expect("selected part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(other_part_path).expect("other part"),
            b"other shard payload"
        );
    }

    #[test]
    fn mutation_journal_lookup_recovers_a_lost_helper_response() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let operation_id = "99999999-9999-9999-9999-999999999999";
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let lost_receipt = session
            .execute_mutation_with_id(
                StorageHelperInvocation {
                    context: context.clone(),
                    operation: operation.clone(),
                },
                operation_id,
            )
            .expect("durable mutation with a lost controller response");

        let lookup = session
            .query_mutation(&context, operation_id)
            .expect("query durable mutation journal");
        lookup
            .validate_for(&context, operation_id, &operation)
            .expect("receipt needed for emergency recovery");
        assert_eq!(lookup.state, MutationRecoveryState::Mutated);
        assert_eq!(
            lookup
                .receipt
                .as_deref()
                .map(|receipt| receipt.response_sha256.as_str()),
            Some(lost_receipt.response_sha256.as_str())
        );

        let first_cleanup = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: operation_id.to_string(),
                },
            })
            .expect("restore mutation after response recovery");
        fs::write(&part_path, b"changed shard payload!").expect("change restored shard");
        assert!(
            session
                .execute(StorageHelperInvocation {
                    context: context.clone(),
                    operation: StorageRecoveryHostOperation::RestoreShard {
                        mutation_operation_id: operation_id.to_string(),
                    },
                })
                .is_err()
        );
        fs::write(&part_path, b"original shard payload").expect("repair restored shard");
        let replayed_cleanup = session
            .execute(StorageHelperInvocation {
                context,
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: operation_id.to_string(),
                },
            })
            .expect("replay terminal cleanup after helper termination");
        assert_eq!(first_cleanup.operation_id, replayed_cleanup.operation_id);
        assert_eq!(
            fs::read(part_path).expect("restored part"),
            b"original shard payload"
        );
    }

    #[test]
    fn verified_superseded_terminal_journal_replays_cleanup_receipt() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        session
            .execute_mutation_with_id(
                StorageHelperInvocation {
                    context: context.clone(),
                    operation,
                },
                operation_id,
            )
            .expect("mutation");
        let superseded_path = part_path.with_extension("superseded");
        fs::rename(&part_path, &superseded_path).expect("retain superseded shard inode");
        fs::write(&part_path, b"original shard payload").expect("superseding repaired shard");
        let post_inspection = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: post_inspection_operation_id,
            ..
        } = post_inspection
        else {
            unreachable!("post inspection fixture returns a mutation operation")
        };
        let journal_root = open_directory(&roots.journal, "journal root").expect("journal root");
        let mut journal = load_journal(&journal_root, operation_id).expect("mutation journal");
        journal.state = JournalState::VerifiedSuperseded;
        journal.terminal_post_inspection_operation_id = Some(post_inspection_operation_id.clone());
        journal.updated_at_ms = now_ms().expect("now");
        persist_journal(&journal_root, &journal).expect("terminal journal");
        let verify = StorageRecoveryHostOperation::VerifySupersededShard {
            mutation_operation_id: operation_id.to_string(),
            post_inspection_operation_id,
        };
        let first = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: verify.clone(),
            })
            .expect("rebuild cleanup receipt");
        let second = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: verify,
            })
            .expect("replay rebuilt cleanup receipt");
        assert_eq!(first.operation_id, second.operation_id);
        assert!(
            session
                .execute(StorageHelperInvocation {
                    context: context.clone(),
                    operation: StorageRecoveryHostOperation::VerifySupersededShard {
                        mutation_operation_id: operation_id.to_string(),
                        post_inspection_operation_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                            .to_string(),
                    },
                })
                .is_err()
        );
        fs::write(&part_path, b"changed superseding shard").expect("change superseding shard");
        assert!(
            session
                .execute(StorageHelperInvocation {
                    context: context.clone(),
                    operation: StorageRecoveryHostOperation::RestoreShard {
                        mutation_operation_id: operation_id.to_string(),
                    },
                })
                .is_err()
        );
        fs::write(&part_path, b"original shard payload").expect("repair superseding shard");
        let restore = session
            .execute(StorageHelperInvocation {
                context,
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: operation_id.to_string(),
                },
            })
            .expect("recover terminal mutation through restore");
        assert_ne!(restore.operation_id, first.operation_id);
        let response: OfflineShardRecoveryResponse =
            serde_json::from_str(&restore.response_body).expect("restore response");
        assert_eq!(
            response.outcome,
            crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired
        );
    }

    #[test]
    fn prepared_journal_recovers_after_helper_dies_post_mutation() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard { byte_offset, .. } = operation.clone()
        else {
            unreachable!("test operation is a mutation")
        };
        let relative_part_path = "bucket/object/data-dir/part.1".to_string();
        let shard_metadata = fs::metadata(&part_path).expect("part metadata");
        let shard_device_id = context.host_generation.device_major_minor.clone();
        let shard_inode = shard_metadata.ino();
        let shard_size_bytes = shard_metadata.len();
        let original_sha256 = sha256_bytes(&fs::read(&part_path).expect("part"));
        let root = open_directory(&roots.volume, "volume root").expect("volume root");
        let part = open_beneath(&root, &relative_part_path, libc::O_RDWR, 0).expect("part fd");
        let mut original = [0_u8; 1];
        part.read_at(&mut original, byte_offset)
            .expect("read original");
        let mutated_byte = original[0] ^ CONTROLLED_SHARD_XOR_MASK;
        let mutated_sha256 = hash_file(&part, Some((byte_offset, mutated_byte))).expect("hash");
        let operation_id = Uuid::new_v4().to_string();
        let journal = MutationJournal {
            schema_version: 1,
            operation_id: operation_id.clone(),
            context_sha256: context_sha256(&context).expect("context digest"),
            scope_sha256: context.scope_sha256.clone(),
            lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
            lease_acquired_at_ms: context.exclusive_access.kubernetes_lease.acquired_at_ms,
            holder_identity: context
                .exclusive_access
                .kubernetes_lease
                .holder_identity
                .clone(),
            operation,
            state: JournalState::Prepared,
            relative_part_path: Some(relative_part_path),
            shard_device_id: Some(shard_device_id),
            shard_inode: Some(shard_inode),
            shard_size_bytes: Some(shard_size_bytes),
            byte_offset: Some(byte_offset),
            original_byte: Some(original[0]),
            mutated_byte: Some(mutated_byte),
            original_sha256: Some(original_sha256),
            mutated_sha256: Some(mutated_sha256),
            reason: None,
            terminal_post_inspection_operation_id: None,
            response_body: None,
            response_sha256: None,
            started_at_ms: now_ms().expect("now"),
            updated_at_ms: now_ms().expect("now"),
        };
        let journal_root = open_directory(&roots.journal, "journal root").expect("journal root");
        persist_journal(&journal_root, &journal).expect("prepared journal");
        part.write_at(&[mutated_byte], byte_offset)
            .expect("simulate mutation before helper death");
        part.sync_all().expect("durable simulated mutation");
        drop(part);

        execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: operation_id,
                },
            },
            &roots,
        )
        .expect("restore prepared journal");
        assert_eq!(
            fs::read(part_path).expect("restored part"),
            b"original shard payload"
        );
    }

    #[test]
    fn partial_published_journal_is_rejected_without_touching_shard() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation_id = Uuid::new_v4().to_string();
        fs::write(
            roots.journal.join(format!("mutation-{operation_id}.json")),
            b"{\"schemaVersion\":1",
        )
        .expect("partial journal");

        assert!(
            execute(
                StorageHelperInvocation {
                    context,
                    operation: StorageRecoveryHostOperation::RestoreShard {
                        mutation_operation_id: operation_id,
                    },
                },
                &roots,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(part_path).expect("untouched part"),
            b"original shard payload"
        );
    }

    #[test]
    fn path_escape_and_symlink_are_rejected_by_openat2() {
        let (_temporary, roots) = test_roots();
        fs::write(roots.volume.join("outside"), b"outside").expect("outside");
        symlink("outside", roots.volume.join("link")).expect("symlink");
        let root = open_directory(&roots.volume, "test root").expect("root");

        assert!(open_beneath(&root, "../outside", libc::O_RDONLY, 0).is_err());
        assert!(open_beneath(&root, "link", libc::O_RDONLY, 0).is_err());
        let system_root = open_directory(Path::new("/"), "system root").expect("system root");
        assert!(
            open_beneath(&system_root, "proc/version", libc::O_RDONLY, 0).is_err(),
            "openat2 must reject crossing from / into the /proc mount"
        );
        assert_eq!(
            STORAGE_RESOLVE_FLAGS,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
        );
    }

    #[test]
    fn second_attempt_cannot_acquire_host_lock_during_session() {
        let (_temporary, roots) = test_roots();
        let context = context_for(&roots);
        let _first = StorageHelperSession::begin(context.clone(), &roots).expect("first session");

        let error = StorageHelperSession::begin(context, &roots)
            .err()
            .expect("second session must not acquire flock");
        assert!(error.to_string().contains("flock"), "{error:#}");
    }

    #[test]
    fn prior_lease_terminal_journals_allow_a_new_attempt() {
        for state in [
            JournalState::Completed,
            JournalState::Restored,
            JournalState::VerifiedSuperseded,
        ] {
            let (_temporary, roots) = test_roots();
            let context = context_for(&roots);
            let journal_root =
                open_directory(&roots.journal, "journal root").expect("journal root");
            let receipt = completed_receipt(
                &context,
                &journal_root,
                StorageRecoveryHostOperation::InspectXlMeta {
                    object_directory: "bucket-1/object".to_string(),
                    bucket: context.identity.bucket.clone(),
                    object_key: "object".to_string(),
                    object_sha256: HASH.to_string(),
                    version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                    selected_part_number: 1,
                    expected_mount_device_id: context.host_generation.device_major_minor.clone(),
                    expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
                },
                &serde_json::json!({"terminal": true}),
                now_ms().expect("now"),
            )
            .expect("terminal journal");
            let mut journal =
                load_journal(&journal_root, &receipt.operation_id).expect("load terminal journal");
            journal.state = state;
            persist_journal(&journal_root, &journal).expect("persist terminal journal state");

            StorageHelperSession::begin(next_lease_generation(context), &roots)
                .expect("terminal journal from an old Lease generation must not fence recovery");
        }
    }

    #[test]
    fn unresolved_mutation_blocks_lease_takeover_by_new_attempt() {
        for unresolved_state in [JournalState::Prepared, JournalState::Mutated] {
            let (_temporary, roots) = test_roots();
            let part_path = roots.volume.join("bucket/object/data-dir/part.1");
            fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
            fs::write(&part_path, b"original shard payload").expect("part");
            let context = context_for(&roots);
            let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
            let mut first = StorageHelperSession::begin(context.clone(), &roots).expect("first");
            let receipt = first
                .execute(StorageHelperInvocation {
                    context: context.clone(),
                    operation,
                })
                .expect("mutation");
            let journal_root =
                open_directory(&roots.journal, "journal root").expect("journal root");
            let mut journal =
                load_journal(&journal_root, &receipt.operation_id).expect("mutation journal");
            journal.state = unresolved_state;
            persist_journal(&journal_root, &journal).expect("unresolved journal state");
            drop(first);

            let error = StorageHelperSession::begin(next_lease_generation(context), &roots)
                .err()
                .expect("new Lease generation must not inherit an unresolved mutation");
            assert!(
                error.to_string().contains("current Lease and holder"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn inode_drift_and_independent_change_quarantine_restore() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mutated = execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation,
            },
            &roots,
        )
        .expect("mutate shard");

        fs::remove_file(&part_path).expect("remove old inode");
        fs::write(&part_path, b"independent replacement").expect("replacement inode");
        let receipt = execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutated.operation_id.clone(),
                },
            },
            &roots,
        )
        .expect("durable quarantine receipt");
        assert!(
            receipt
                .response_body
                .contains("\"outcome\":\"quarantined\"")
        );
        StorageRecoveryCleanupProof::BitrotQuarantined {
            restore_receipt: Box::new(receipt),
        }
        .validate_for(&context)
        .expect_err("quarantine must not release attempt ownership");
        let journal = load_journal(
            &open_directory(&roots.journal, "journal root").expect("journal root"),
            &mutated.operation_id,
        )
        .expect("quarantine journal");
        assert_eq!(journal.state, JournalState::Quarantined);

        let mut next_attempt = context;
        next_attempt.identity.run_id = "run-2".to_string();
        next_attempt.attempt_id = "attempt-2".to_string();
        next_attempt
            .exclusive_access
            .kubernetes_lease
            .holder_identity = "run-2/attempt-2".to_string();
        let error = StorageHelperSession::begin(next_attempt, &roots)
            .err()
            .expect("quarantine must fence a new attempt after Lease takeover");
        assert!(
            error.to_string().contains("repair acknowledgement"),
            "{error:#}"
        );
    }
}
