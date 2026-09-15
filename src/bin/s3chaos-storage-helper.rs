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

use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use s3chaos::fault::fresh_volume::{FreshVolumeHostProbeRequest, run_fresh_volume_host_probe};
use s3chaos::fault::storage_recovery_helper::{
    StaleOfflineHelperRequest, StorageHelperSession, StorageHelperSessionRequest,
    StorageHelperSessionResponse, execute_stale_offline_helper,
};

const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.as_slice().get(1).map(String::as_str) == Some("--stale-one-shot") {
        ensure!(args.len() == 2, "stale one-shot accepts no extra arguments");
        return run_stale_one_shot();
    }
    if args.as_slice().get(1).map(String::as_str) == Some("hold") {
        ensure!(args.len() == 2, "storage helper hold accepts no arguments");
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(60 * 60));
        }
    }
    if args.as_slice().get(1).map(String::as_str) == Some("probe-fresh-volume") {
        ensure!(
            args.len() == 2,
            "fresh-volume probe accepts no free-form arguments"
        );
        let request: FreshVolumeHostProbeRequest =
            serde_json::from_reader(std::io::stdin().lock().take(MAX_REQUEST_BYTES + 1))
                .context("decode typed fresh-volume host probe request")?;
        let response = run_fresh_volume_host_probe(&request)?;
        serde_json::to_writer(std::io::stdout().lock(), &response)
            .context("write typed fresh-volume host probe response")?;
        return Ok(());
    }
    ensure!(
        args.len() == 1,
        "storage helper accepts only closed hold, probe-fresh-volume, and stale one-shot operations"
    );
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut output = std::io::stdout().lock();
    let first = read_request(&mut input)?.context("storage helper session request is empty")?;
    let StorageHelperSessionRequest::Begin { context } = first else {
        bail!("storage helper session must begin with a typed begin request")
    };
    let context = *context;
    let mut session = match StorageHelperSession::begin_default(context.clone()) {
        Ok(session) => session,
        Err(error) => {
            write_error(&mut output, &format!("{error:#}"))?;
            return Err(error);
        }
    };
    write_response(
        &mut output,
        &StorageHelperSessionResponse::Ready {
            scope_sha256: context.scope_sha256,
        },
    )?;

    loop {
        let request = read_request(&mut input)?
            .context("storage helper session ended before typed cleanup")?;
        match request {
            StorageHelperSessionRequest::Begin { .. } => {
                write_error(&mut output, "storage helper session is already active")?;
            }
            StorageHelperSessionRequest::Execute { invocation } => {
                match session.execute(*invocation) {
                    Ok(receipt) => write_response(
                        &mut output,
                        &StorageHelperSessionResponse::Receipt {
                            receipt: Box::new(receipt),
                        },
                    )?,
                    Err(error) => write_error(&mut output, &format!("{error:#}"))?,
                }
            }
            StorageHelperSessionRequest::StaleExecute { context, request } => {
                match session.execute_stale(&context, &request) {
                    Ok(response) => write_response(
                        &mut output,
                        &StorageHelperSessionResponse::StaleResponse {
                            response: Box::new(response),
                        },
                    )?,
                    Err(error) => write_error(&mut output, &format!("{error:#}"))?,
                }
            }
            StorageHelperSessionRequest::Finish { context, cleanup } => {
                match session.finish(&context, &cleanup) {
                    Ok(()) => {
                        write_response(
                            &mut output,
                            &StorageHelperSessionResponse::Finished {
                                scope_sha256: context.scope_sha256,
                            },
                        )?;
                        return Ok(());
                    }
                    Err(error) => write_error(&mut output, &format!("{error:#}"))?,
                }
            }
        }
    }
}

fn run_stale_one_shot() -> Result<()> {
    let mut body = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut body)
        .context("read stale offline helper request")?;
    ensure!(
        !body.is_empty() && body.len() <= MAX_REQUEST_BYTES as usize,
        "stale offline helper request is empty or oversized"
    );
    let request = serde_json::from_slice::<StaleOfflineHelperRequest>(&body)
        .context("decode stale offline helper request")?;
    let response = execute_stale_offline_helper(request)?;
    serde_json::to_writer(std::io::stdout().lock(), &response)
        .context("write stale offline helper response")?;
    Ok(())
}

fn read_request(input: &mut impl BufRead) -> Result<Option<StorageHelperSessionRequest>> {
    let mut body = Vec::new();
    let count = input
        .take(MAX_REQUEST_BYTES + 1)
        .read_until(b'\n', &mut body)
        .context("read typed storage helper session request")?;
    if count == 0 {
        return Ok(None);
    }
    ensure!(
        body.len() <= MAX_REQUEST_BYTES as usize,
        "typed storage helper session request is oversized"
    );
    while body
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        body.pop();
    }
    ensure!(
        !body.is_empty(),
        "typed storage helper session request is empty"
    );
    serde_json::from_slice(&body)
        .context("decode typed storage helper session request")
        .map(Some)
}

fn write_error(output: &mut impl Write, message: &str) -> Result<()> {
    write_response(
        output,
        &StorageHelperSessionResponse::Error {
            message: message.to_string(),
        },
    )
}

fn write_response(output: &mut impl Write, response: &StorageHelperSessionResponse) -> Result<()> {
    serde_json::to_writer(&mut *output, response).context("write typed storage helper response")?;
    output.write_all(b"\n")?;
    output
        .flush()
        .context("flush typed storage helper response")
}
