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
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

use super::runs::{private_directory, write_file};

include!(concat!(env!("OUT_DIR"), "/resources.rs"));

pub fn materialize(data: &Path) -> Result<PathBuf> {
    let mut hash = Sha256::new();
    for (name, content) in FILES {
        hash.update(name.as_bytes());
        hash.update(content.as_bytes());
    }
    let root = data.join("resources").join(hex::encode(hash.finalize()));
    private_directory(&root)?;
    for (name, content) in FILES {
        let path = root.join(name);
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() == content.len() as u64
                    && fs::read(&path)? == content.as_bytes(),
                "installed resource has changed: {}",
                path.display()
            );
        } else {
            write_file(&path, content.as_bytes())?;
        }
    }
    Ok(root.canonicalize()?)
}

pub fn suite_path(resources: &Path, kind: &str, selection: &str) -> Result<PathBuf> {
    let selected = Path::new(selection);
    if selected.is_file() {
        return Ok(selected.canonicalize()?);
    }
    super::config::validate_name(selection)?;
    let path = resources
        .join(kind)
        .join("examples")
        .join(format!("{selection}.yaml"));
    ensure!(
        path.is_file(),
        "unknown {kind} suite {selection:?}; provide an existing suite YAML path or run s3chaos list suites"
    );
    Ok(path)
}
