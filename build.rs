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

use std::{env, fs, path::Path, process::Command};

fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").expect("manifest directory");
    let mut files = Vec::new();
    for directory in ["fault/examples", "protocol/examples", "protocol/mint"] {
        println!("cargo:rerun-if-changed={directory}");
        for entry in fs::read_dir(Path::new(&root).join(directory)).expect("bundled directory") {
            let path = entry.expect("bundled entry").path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                files.push(path);
            }
        }
    }
    println!("cargo:rerun-if-changed=scripts/fault-test.sh");
    files.push(Path::new(&root).join("scripts/fault-test.sh"));
    files.sort();
    let mut generated = String::from("pub const FILES: &[(&str, &str)] = &[\n");
    for path in files {
        let name = path
            .strip_prefix(&root)
            .expect("relative resource")
            .to_string_lossy();
        generated.push_str(&format!(
            "({name:?}, include_str!({:?})),\n",
            path.to_string_lossy()
        ));
    }
    generated.push_str("];\n");
    fs::write(
        Path::new(&env::var_os("OUT_DIR").expect("output directory")).join("resources.rs"),
        generated,
    )
    .expect("write resource table");
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=S3CHAOS_BUILD_REVISION={revision}");
    let reference = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    for revision_file in std::iter::once("HEAD").chain(reference.as_deref()) {
        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "--git-path", revision_file])
            .output()
            && output.status.success()
        {
            println!(
                "cargo:rerun-if-changed={}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
    }
}
