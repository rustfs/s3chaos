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
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use super::config::{Target, validate_name};

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: u32,
    pub id: String,
    pub kind: String,
    pub target: String,
    pub target_config: Target,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub state: String,
    pub result: String,
    pub exit_code: Option<i32>,
    pub artifacts: String,
    pub tool_version: String,
    pub source_revision: String,
    pub parent_run: Option<String>,
    pub suite: Option<String>,
    pub scenario: Option<String>,
    pub qualification: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub process: Option<ProcessIdentity>,
    #[serde(default)]
    pub worker_process: Option<ProcessIdentity>,
    #[serde(default)]
    pub reproduction_image_override: bool,
}

impl RunRecord {
    pub fn create(
        data: &Path,
        kind: &str,
        target: &str,
        target_config: Target,
        parent_run: Option<String>,
    ) -> Result<(Self, PathBuf)> {
        validate_name(target)?;
        let id = Uuid::new_v4().to_string();
        let root = data.join("runs").join(&id);
        private_directory(&root)?;
        let root = root.canonicalize()?;
        let record = Self {
            schema_version: 1,
            id,
            kind: kind.into(),
            target: target.into(),
            target_config,
            started_at: timestamp()?,
            finished_at: None,
            state: "preparing".into(),
            result: "preparing".into(),
            exit_code: None,
            artifacts: "artifacts".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            source_revision: env!("S3CHAOS_BUILD_REVISION").into(),
            parent_run,
            suite: None,
            scenario: None,
            qualification: None,
            error: None,
            process: ProcessIdentity::current(),
            worker_process: None,
            reproduction_image_override: false,
        };
        record.save(&root)?;
        Ok((record, root))
    }

    pub fn load(root: &Path) -> Result<Self> {
        let record: Self = read_json(&root.join("record.json"))?;
        ensure!(
            record.schema_version == 1 && record.artifacts == "artifacts",
            "unsupported run record"
        );
        validate_name(&record.id)?;
        ensure!(
            ["fault", "protocol", "mint"].contains(&record.kind.as_str()),
            "unsupported run kind"
        );
        Ok(record)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= 64 * 1024,
            "run configuration exceeds the 64 KiB record limit"
        );
        write_file(&root.join("record.json"), &bytes)
    }
}

pub use crate::framework::process_identity::ProcessIdentity;

pub fn timestamp() -> Result<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

pub fn resolve_run(data: &Path, id: &str) -> Result<PathBuf> {
    let path = if Path::new(id).is_dir() {
        PathBuf::from(id)
    } else {
        validate_name(id)?;
        data.join("runs").join(id)
    };
    ensure!(
        !fs::symlink_metadata(&path)
            .with_context(|| format!("run {id:?} was not found; use s3chaos runs"))?
            .file_type()
            .is_symlink(),
        "run root must not be a symlink"
    );
    path.canonicalize().context("resolve run directory")
}

pub fn private_directory(path: &Path) -> Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "directory must not be a symlink: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_RECORD_BYTES,
        "invalid or oversized record {}",
        path.display()
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "record exceeds size limit"
    );
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_file(path, &serde_json::to_vec_pretty(value)?)
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    private_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "refusing to replace non-file {}",
            path.display()
        );
    }
    let temporary = parent.join(format!(".write-{}", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("persist {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_failures_have_independent_durable_records() {
        let data = tempfile::tempdir().unwrap();
        let (first, root) =
            RunRecord::create(data.path(), "fault", "lab", Target::default(), None).unwrap();
        let (second, _) =
            RunRecord::create(data.path(), "fault", "lab", Target::default(), None).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(RunRecord::load(&root).unwrap().state, "preparing");
        assert_eq!(resolve_run(data.path(), &first.id).unwrap(), root);
        assert!(resolve_run(data.path(), "../outside").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn records_cannot_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("outside");
        fs::write(&destination, "original").unwrap();
        let link = dir.path().join("record.json");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert!(write_json(&link, &true).is_err());
        assert_eq!(fs::read_to_string(destination).unwrap(), "original");
    }
}
