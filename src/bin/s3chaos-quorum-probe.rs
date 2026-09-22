// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, ensure};
use s3chaos::fault::quorum::probe::{ProbeRequest, execute};
use std::io::Read;

fn main() -> Result<()> {
    ensure!(
        std::env::args().count() == 1,
        "probe accepts only a typed JSON request on stdin"
    );
    let request: ProbeRequest = serde_json::from_reader(std::io::stdin().lock().take(64 * 1024))?;
    let response = execute(request)?;
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}
