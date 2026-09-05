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

use anyhow::{Context, Result, ensure};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::Region,
    error::SdkError,
    primitives::ByteStream,
    types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, VersioningConfiguration,
    },
};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};
use tokio::time::{Instant, timeout};

use crate::fault::history::{
    ByteRange, OperationKind, OperationOutcome, OperationRecord, PayloadRef, Recorder,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSpec {
    pub key: String,
    pub size_bytes: usize,
    pub sha256: String,
    seed: u64,
    index: usize,
}

#[derive(Debug)]
pub struct PreparedObject {
    pub spec: ObjectSpec,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct StagedMultipartUpload {
    pub(crate) spec: ObjectSpec,
    upload_id: String,
    completed_parts: Vec<CompletedPart>,
}

pub(crate) struct StagedMultipartCleanupGuard {
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl StagedMultipartCleanupGuard {
    pub(crate) fn new(
        client: S3WorkloadClient,
        recorder: Recorder,
        staged: StagedMultipartUpload,
    ) -> Self {
        let key = staged.spec.key.clone();
        Self::from_cleanup(move || {
            let thread = std::thread::Builder::new()
                .name("s3chaos-multipart-cleanup".to_string())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("build multipart cancellation cleanup runtime")?;
                    runtime.block_on(client.abort_staged_multipart_object(&staged, &recorder))
                });
            match thread {
                Ok(thread) => match thread.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!(
                        "warning: failed to abort staged multipart upload for {key} during cancellation: {error:#}"
                    ),
                    Err(_) => eprintln!(
                        "warning: staged multipart cancellation cleanup thread panicked for {key}"
                    ),
                },
                Err(error) => eprintln!(
                    "warning: failed to start staged multipart cancellation cleanup for {key}: {error}"
                ),
            }
        })
    }

    fn from_cleanup(cleanup: impl FnOnce() + Send + 'static) -> Self {
        Self {
            cleanup: Some(Box::new(cleanup)),
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for StagedMultipartCleanupGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSizeClass {
    pub size_bytes: usize,
    pub object_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadOperationMix {
    pub put: u32,
    pub overwrite: u32,
    pub get: u32,
    pub list: u32,
    pub delete: u32,
    pub multipart: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadPayloadClass {
    pub size_bytes: usize,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadPayloadDistribution {
    pub classes: Vec<WorkloadPayloadClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadHotspot {
    pub object_percent: u8,
    pub operation_percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkloadOperation {
    Put,
    Overwrite,
    Get,
    List,
    Delete,
    Multipart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkloadPlan {
    pub seed: u64,
    pub generator: String,
    pub object_count: usize,
    pub concurrency: usize,
    pub operation_mix: WorkloadOperationMix,
    pub total_payload_bytes: u64,
    pub size_distribution: Vec<WorkloadSizeClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspot: Option<WorkloadHotspot>,
    sizes: Vec<usize>,
}

#[derive(Debug, Deserialize)]
struct SerializedWorkloadPlan {
    seed: u64,
    generator: String,
    object_count: usize,
    concurrency: usize,
    #[serde(default)]
    operation_mix: WorkloadOperationMix,
    total_payload_bytes: u64,
    size_distribution: Vec<WorkloadSizeClass>,
    #[serde(default)]
    hotspot: Option<WorkloadHotspot>,
}

#[derive(Clone)]
pub struct S3WorkloadClient {
    client: Client,
    bucket: String,
    request_timeout: Duration,
    mutation_deadline: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersionEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub is_latest: bool,
    pub is_delete_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetObjectResult {
    pub outcome: OperationOutcome,
    pub http_status: Option<u16>,
    pub error: Option<String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWriteResult {
    pub write_outcome: OperationOutcome,
    pub verify_get_outcome: Option<OperationOutcome>,
    pub verified: bool,
}

struct RecordedDelete {
    record: OperationRecord,
    is_delete_marker: Option<bool>,
}

impl ObjectSpec {
    pub fn key_prefix(run_id: &str) -> String {
        format!("fault-test/{run_id}/")
    }

    pub fn matches_body(&self, body: &[u8]) -> bool {
        body.len() == self.size_bytes && sha256_hex(body) == self.sha256
    }

    pub fn prepare_seeded(
        run_id: &str,
        index: usize,
        size_bytes: usize,
        seed: u64,
    ) -> PreparedObject {
        let key = format!("{}object-{index:06}", Self::key_prefix(run_id));
        let body = seeded_bytes(seed, index, size_bytes);
        let sha256 = sha256_hex(&body);

        PreparedObject {
            spec: Self {
                key,
                size_bytes,
                sha256,
                seed,
                index,
            },
            body,
        }
    }

    /// A zero-byte directory-marker object whose key ends in `/` (the S3
    /// "folder placeholder" pattern). RustFS routes trailing-slash keys through
    /// a distinct store-layer directory-object encoding, so exercising them
    /// through the full prefill -> fault -> recovery -> GET/DELETE/LIST cycle
    /// covers a code path plain object keys never reach (notably the
    /// directory-key delete path, rustfs/backlog#798). Size 0 keeps it off the
    /// erasure-shard and ranged-read paths.
    pub fn prepare_directory_marker(run_id: &str, index: usize, seed: u64) -> PreparedObject {
        let key = format!("{}dir-{index:06}/", Self::key_prefix(run_id));
        let body = Vec::new();
        let sha256 = sha256_hex(&body);

        PreparedObject {
            spec: Self {
                key,
                size_bytes: 0,
                sha256,
                seed,
                index,
            },
            body,
        }
    }

    pub fn is_directory_marker(&self) -> bool {
        self.key.ends_with('/')
    }

    pub fn prepare(&self) -> PreparedObject {
        let body = seeded_bytes(self.seed, self.index, self.size_bytes);
        debug_assert_eq!(sha256_hex(&body), self.sha256);
        PreparedObject {
            spec: self.clone(),
            body,
        }
    }

    pub fn prepare_overwrite(&self, variant: u64) -> PreparedObject {
        let seed = self.seed ^ variant.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let body = seeded_bytes(seed, self.index, self.size_bytes);
        let sha256 = sha256_hex(&body);
        PreparedObject {
            spec: Self {
                key: self.key.clone(),
                size_bytes: self.size_bytes,
                sha256,
                seed,
                index: self.index,
            },
            body,
        }
    }
}

impl WorkloadPlan {
    const GENERATOR: &'static str = "splitmix64-v1";

    pub fn seeded(seed: u64, object_count: usize, concurrency: usize) -> Self {
        Self::seeded_unchecked(
            seed,
            object_count,
            concurrency,
            WorkloadOperationMix::default(),
            None,
            None,
        )
    }

    pub fn seeded_with_mix(
        seed: u64,
        object_count: usize,
        concurrency: usize,
        operation_mix: WorkloadOperationMix,
    ) -> Result<Self> {
        Self::seeded_with_profile(seed, object_count, concurrency, operation_mix, None, None)
    }

    pub fn seeded_with_profile(
        seed: u64,
        object_count: usize,
        concurrency: usize,
        operation_mix: WorkloadOperationMix,
        payload_distribution: Option<WorkloadPayloadDistribution>,
        hotspot: Option<WorkloadHotspot>,
    ) -> Result<Self> {
        operation_mix.validate()?;
        if let Some(payload_distribution) = &payload_distribution {
            payload_distribution.validate()?;
        }
        if let Some(hotspot) = hotspot {
            hotspot.validate()?;
        }
        Ok(Self::seeded_unchecked(
            seed,
            object_count,
            concurrency,
            operation_mix,
            payload_distribution,
            hotspot,
        ))
    }

    fn seeded_unchecked(
        seed: u64,
        object_count: usize,
        concurrency: usize,
        operation_mix: WorkloadOperationMix,
        payload_distribution: Option<WorkloadPayloadDistribution>,
        hotspot: Option<WorkloadHotspot>,
    ) -> Self {
        let payload_distribution = payload_distribution.unwrap_or_default();
        let size_distribution = payload_distribution.to_size_distribution(object_count);
        let mut sizes = Vec::with_capacity(object_count);
        for class in &size_distribution {
            sizes.extend(std::iter::repeat_n(class.size_bytes, class.object_count));
        }

        shuffle_sizes(&mut sizes, seed);
        let total_payload_bytes = sizes.iter().map(|size| *size as u64).sum();
        Self {
            seed,
            generator: Self::GENERATOR.to_string(),
            object_count,
            concurrency,
            operation_mix,
            total_payload_bytes,
            size_distribution,
            hotspot,
            sizes,
        }
    }

    pub fn size_at(&self, index: usize) -> usize {
        self.sizes[index]
    }

    pub fn existing_object_offset(&self, offset: usize, existing_count: usize) -> usize {
        let Some(hotspot) = self.hotspot else {
            return offset % existing_count;
        };
        let hotspot_count = (existing_count
            .saturating_mul(usize::from(hotspot.object_percent))
            .saturating_add(99)
            / 100)
            .clamp(1, existing_count);
        let mut generator =
            SplitMix64::new(self.seed ^ (offset as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
        let use_hotspot = generator.next_u64() % 100 < u64::from(hotspot.operation_percent);
        if use_hotspot || hotspot_count == existing_count {
            (generator.next_u64() as usize) % hotspot_count
        } else {
            let cold_count = existing_count - hotspot_count;
            hotspot_count + (generator.next_u64() as usize) % cold_count
        }
    }

    fn from_serialized(raw: SerializedWorkloadPlan) -> std::result::Result<Self, String> {
        if raw.generator != Self::GENERATOR {
            return Err(format!("unsupported workload generator {}", raw.generator));
        }
        if !(1..=raw.object_count).contains(&raw.concurrency) {
            return Err(format!(
                "workload concurrency {} must be between 1 and object_count {}",
                raw.concurrency, raw.object_count
            ));
        }
        raw.operation_mix
            .validate()
            .map_err(|error| error.to_string())?;
        if let Some(hotspot) = raw.hotspot {
            hotspot.validate().map_err(|error| error.to_string())?;
        }

        let distributed_objects =
            raw.size_distribution
                .iter()
                .try_fold(0usize, |total, class| {
                    total.checked_add(class.object_count).ok_or_else(|| {
                        "workload size_distribution object_count overflowed".to_string()
                    })
                })?;
        if distributed_objects != raw.object_count {
            return Err(format!(
                "workload size_distribution object_count {} does not match object_count {}",
                distributed_objects, raw.object_count
            ));
        }

        let distributed_payload = raw
            .size_distribution
            .iter()
            .try_fold(0u64, |total, class| {
                if class.size_bytes == 0 {
                    return Err("workload size class size_bytes must be positive".to_string());
                }
                let class_payload = (class.size_bytes as u64)
                    .checked_mul(class.object_count as u64)
                    .ok_or_else(|| "workload size_distribution payload overflowed".to_string())?;
                total.checked_add(class_payload).ok_or_else(|| {
                    "workload size_distribution total payload overflowed".to_string()
                })
            })?;
        if distributed_payload != raw.total_payload_bytes {
            return Err(format!(
                "workload size_distribution payload {} does not match total_payload_bytes {}",
                distributed_payload, raw.total_payload_bytes
            ));
        }

        let mut sizes = Vec::with_capacity(raw.object_count);
        for class in &raw.size_distribution {
            sizes.extend(std::iter::repeat_n(class.size_bytes, class.object_count));
        }
        shuffle_sizes(&mut sizes, raw.seed);

        Ok(Self {
            seed: raw.seed,
            generator: raw.generator,
            object_count: raw.object_count,
            concurrency: raw.concurrency,
            operation_mix: raw.operation_mix,
            total_payload_bytes: raw.total_payload_bytes,
            size_distribution: raw.size_distribution,
            hotspot: raw.hotspot,
            sizes,
        })
    }
}

impl WorkloadPayloadDistribution {
    const MAX_CLASSES: usize = 8;
    const MAX_WEIGHT: u32 = 100;
    const MAX_SIZE_BYTES: usize = 64 * 1024 * 1024;

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.classes.is_empty(),
            "workload.payloadDistribution must not be empty"
        );
        ensure!(
            self.classes.len() <= Self::MAX_CLASSES,
            "workload.payloadDistribution must contain at most {} classes",
            Self::MAX_CLASSES
        );
        for class in &self.classes {
            ensure!(
                (1..=Self::MAX_SIZE_BYTES).contains(&class.size_bytes),
                "workload.payloadDistribution.sizeBytes must be between 1 and {}",
                Self::MAX_SIZE_BYTES
            );
            ensure!(
                (1..=Self::MAX_WEIGHT).contains(&class.weight),
                "workload.payloadDistribution.weight must be between 1 and {}",
                Self::MAX_WEIGHT
            );
        }
        Ok(())
    }

    fn to_size_distribution(&self, object_count: usize) -> Vec<WorkloadSizeClass> {
        let total_weight = self
            .classes
            .iter()
            .map(|class| class.weight as usize)
            .sum::<usize>();
        let mut assigned = 0usize;
        self.classes
            .iter()
            .enumerate()
            .map(|(index, class)| {
                let object_count_for_class = if index + 1 == self.classes.len() {
                    object_count.saturating_sub(assigned)
                } else {
                    object_count.saturating_mul(class.weight as usize) / total_weight
                };
                assigned = assigned.saturating_add(object_count_for_class);
                WorkloadSizeClass {
                    size_bytes: class.size_bytes,
                    object_count: object_count_for_class,
                }
            })
            .collect()
    }
}

impl Default for WorkloadPayloadDistribution {
    fn default() -> Self {
        Self {
            classes: vec![
                WorkloadPayloadClass {
                    size_bytes: 4 * 1024,
                    weight: 85,
                },
                WorkloadPayloadClass {
                    size_bytes: 16 * 1024,
                    weight: 10,
                },
                WorkloadPayloadClass {
                    size_bytes: 8 * 1024 * 1024,
                    weight: 4,
                },
                WorkloadPayloadClass {
                    size_bytes: 16 * 1024 * 1024,
                    weight: 1,
                },
            ],
        }
    }
}

impl WorkloadHotspot {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (1..=100).contains(&self.object_percent),
            "workload.hotspot.objectPercent must be between 1 and 100"
        );
        ensure!(
            (1..=100).contains(&self.operation_percent),
            "workload.hotspot.operationPercent must be between 1 and 100"
        );
        Ok(())
    }
}

impl WorkloadOperationMix {
    const MAX_WEIGHT: u32 = 100;

    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("put", self.put),
            ("overwrite", self.overwrite),
            ("get", self.get),
            ("list", self.list),
            ("delete", self.delete),
            ("multipart", self.multipart),
        ] {
            ensure!(
                (1..=Self::MAX_WEIGHT).contains(&value),
                "workload.operationWeights.{name} must be between 1 and {}",
                Self::MAX_WEIGHT
            );
        }
        Ok(())
    }

    pub(crate) fn operation_at(self, offset: usize) -> WorkloadOperation {
        let slot = offset as u64 % self.total_weight();
        let mut cursor = u64::from(self.put);
        if slot < cursor {
            return WorkloadOperation::Put;
        }
        cursor += u64::from(self.overwrite);
        if slot < cursor {
            return WorkloadOperation::Overwrite;
        }
        cursor += u64::from(self.get);
        if slot < cursor {
            return WorkloadOperation::Get;
        }
        cursor += u64::from(self.list);
        if slot < cursor {
            return WorkloadOperation::List;
        }
        cursor += u64::from(self.delete);
        if slot < cursor {
            return WorkloadOperation::Delete;
        }
        WorkloadOperation::Multipart
    }

    pub fn total_weight(self) -> u64 {
        u64::from(self.put)
            + u64::from(self.overwrite)
            + u64::from(self.get)
            + u64::from(self.list)
            + u64::from(self.delete)
            + u64::from(self.multipart)
    }
}

impl Default for WorkloadOperationMix {
    fn default() -> Self {
        Self {
            put: 1,
            overwrite: 1,
            get: 1,
            list: 1,
            delete: 1,
            multipart: 1,
        }
    }
}

impl<'de> Deserialize<'de> for WorkloadPlan {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializedWorkloadPlan::deserialize(deserializer)?;
        Self::from_serialized(raw).map_err(de::Error::custom)
    }
}

impl S3WorkloadClient {
    pub async fn new(
        endpoint: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        request_timeout: Duration,
    ) -> Result<Self> {
        let credentials = Credentials::new(
            access_key.into(),
            secret_key.into(),
            None,
            None,
            "rustfs-fault-test-static-credentials",
        );
        let shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(credentials)
            .endpoint_url(endpoint.into())
            .load()
            .await;
        let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
            .force_path_style(true)
            .build();

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: bucket.into(),
            request_timeout,
            mutation_deadline: None,
        })
    }

    pub(crate) fn for_quiet_mutation(&self, deadline: Instant) -> Self {
        let mut client = self.clone();
        client.client = Client::from_conf(
            self.client
                .config()
                .to_builder()
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .build(),
        );
        client.mutation_deadline = Some(deadline);
        client
    }

    async fn mutation_request<F: Future>(&self, request: F) -> std::result::Result<F::Output, ()> {
        let duration = self
            .mutation_deadline
            .map_or(self.request_timeout, |deadline| {
                self.request_timeout
                    .min(deadline.saturating_duration_since(Instant::now()))
            });
        if duration.is_zero() {
            return Err(());
        }
        timeout(duration, request).await.map_err(|_| ())
    }

    pub async fn create_bucket(&self, recorder: &Recorder) -> Result<OperationOutcome> {
        let record = recorder.begin(
            OperationKind::CreateBucket,
            self.bucket.clone(),
            None,
            None,
            None,
        );
        let result = timeout(
            self.request_timeout,
            self.client.create_bucket().bucket(&self.bucket).send(),
        )
        .await;

        match result {
            Ok(Ok(_)) => {
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(OperationOutcome::Ok)
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("create bucket failed: {error}")),
                )?;
                Ok(outcome)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("create bucket timed out".to_string()),
                )?;
                Ok(OperationOutcome::Timeout)
            }
        }
    }

    pub async fn put_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<OperationOutcome> {
        Ok(self.put_object_record(object, recorder).await?.outcome)
    }

    pub async fn put_object_record(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<OperationRecord> {
        let spec = &object.spec;
        let mut record = recorder.begin(
            OperationKind::Put,
            self.bucket.clone(),
            Some(spec.key.clone()),
            Some(spec.sha256.clone()),
            Some(spec.size_bytes),
        );
        // The body is fully determined by (seed, index, size); recording the
        // generator inputs lets the checker regenerate the exact bytes when
        // verifying ranged GET slices against this committed value.
        record.payload_ref = Some(PayloadRef {
            seed: spec.seed,
            index: spec.index,
        });
        let result = self
            .mutation_request(
                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(&spec.key)
                    .body(ByteStream::from(object.body.clone()))
                    .send(),
            )
            .await;

        match result {
            Ok(Ok(output)) => {
                let mut record = record;
                record.version_id = output.version_id().map(str::to_string);
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("put object failed: {error}")),
                )
            }
            Err(_) => recorder.finish(
                record,
                OperationOutcome::Timeout,
                None,
                Some("put object timed out".to_string()),
            ),
        }
    }

    pub async fn enable_bucket_versioning(&self, recorder: &Recorder) -> Result<OperationOutcome> {
        let record = recorder.begin(
            OperationKind::PutBucketVersioning,
            self.bucket.clone(),
            None,
            None,
            None,
        );
        let result = timeout(
            self.request_timeout,
            self.client
                .put_bucket_versioning()
                .bucket(&self.bucket)
                .versioning_configuration(
                    VersioningConfiguration::builder()
                        .status(BucketVersioningStatus::Enabled)
                        .build(),
                )
                .send(),
        )
        .await;

        match result {
            Ok(Ok(_)) => {
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(OperationOutcome::Ok)
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("put bucket versioning failed: {error}")),
                )?;
                Ok(outcome)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("put bucket versioning timed out".to_string()),
                )?;
                Ok(OperationOutcome::Timeout)
            }
        }
    }

    pub async fn get_object(&self, key: &str, recorder: &Recorder) -> Result<Option<Vec<u8>>> {
        Ok(self.get_object_result(key, recorder).await?.body)
    }

    pub async fn get_object_result(
        &self,
        key: &str,
        recorder: &Recorder,
    ) -> Result<GetObjectResult> {
        self.get_object_result_inner(key, None, recorder).await
    }

    pub async fn get_object_version_result(
        &self,
        key: &str,
        version_id: &str,
        recorder: &Recorder,
    ) -> Result<GetObjectResult> {
        self.get_object_result_inner(key, Some(version_id), recorder)
            .await
    }

    /// Ranged GET: requests `bytes=offset..offset+length-1` and records the
    /// returned slice (the record's `value_sha256`/`size_bytes` describe the
    /// slice, with `range` set so the checker verifies it against the
    /// regenerated slice of a committed value instead of the whole-object
    /// hash). A 200 full-body reply to a range request is recorded as Failed:
    /// silently ignoring the Range header would otherwise let every range
    /// read degenerate into a whole-object read and hide broken range
    /// handling.
    pub async fn get_object_range_result(
        &self,
        key: &str,
        range: ByteRange,
        recorder: &Recorder,
    ) -> Result<GetObjectResult> {
        let mut record = recorder.begin(
            OperationKind::Get,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        record.range = Some(range);
        let end = range.offset + range.length - 1;
        let response = timeout(
            self.request_timeout,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .range(format!("bytes={}-{}", range.offset, end))
                .send(),
        )
        .await;

        let output = match response {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("ranged get failed: {error}")),
                )?;
                return Ok(GetObjectResult {
                    outcome,
                    http_status: sdk_error_status(&error),
                    error: Some(format!("ranged get failed: {error}")),
                    body: None,
                });
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("ranged get timed out".to_string()),
                )?;
                return Ok(GetObjectResult {
                    outcome: OperationOutcome::Timeout,
                    http_status: None,
                    error: Some("ranged get timed out".to_string()),
                    body: None,
                });
            }
        };

        let body = timeout(self.request_timeout, output.body.collect()).await;
        match body {
            Ok(Ok(bytes)) => {
                let body = bytes.into_bytes().to_vec();
                record.value_sha256 = Some(sha256_hex(&body));
                record.size_bytes = Some(body.len());
                if body.len() as u64 != range.length {
                    let error = format!(
                        "ranged get returned {} bytes for a {}-byte range request",
                        body.len(),
                        range.length
                    );
                    recorder.finish(
                        record,
                        OperationOutcome::Failed,
                        Some(206),
                        Some(error.clone()),
                    )?;
                    return Ok(GetObjectResult {
                        outcome: OperationOutcome::Failed,
                        http_status: Some(206),
                        error: Some(error),
                        body: Some(body),
                    });
                }
                recorder.finish(record, OperationOutcome::Ok, Some(206), None)?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Ok,
                    http_status: Some(206),
                    error: None,
                    body: Some(body),
                })
            }
            Ok(Err(error)) => {
                let error = format!("ranged get body read failed: {error}");
                recorder.finish(
                    record,
                    OperationOutcome::Unknown,
                    Some(206),
                    Some(error.clone()),
                )?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Unknown,
                    http_status: Some(206),
                    error: Some(error),
                    body: None,
                })
            }
            Err(_) => {
                let error = "ranged get body read timed out".to_string();
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    Some(206),
                    Some(error.clone()),
                )?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Timeout,
                    http_status: Some(206),
                    error: Some(error),
                    body: None,
                })
            }
        }
    }

    async fn get_object_result_inner(
        &self,
        key: &str,
        version_id: Option<&str>,
        recorder: &Recorder,
    ) -> Result<GetObjectResult> {
        let mut record = recorder.begin(
            OperationKind::Get,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        record.version_id = version_id.map(str::to_string);
        let response = timeout(
            self.request_timeout,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .set_version_id(version_id.map(str::to_string))
                .send(),
        )
        .await;

        let output = match response {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("get object failed: {error}")),
                )?;
                return Ok(GetObjectResult {
                    outcome,
                    http_status: sdk_error_status(&error),
                    error: Some(format!("get object failed: {error}")),
                    body: None,
                });
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("get object timed out".to_string()),
                )?;
                return Ok(GetObjectResult {
                    outcome: OperationOutcome::Timeout,
                    http_status: None,
                    error: Some("get object timed out".to_string()),
                    body: None,
                });
            }
        };

        let body = timeout(self.request_timeout, output.body.collect()).await;
        match body {
            Ok(Ok(bytes)) => {
                let body = bytes.into_bytes().to_vec();
                let mut record = record;
                record.value_sha256 = Some(sha256_hex(&body));
                record.size_bytes = Some(body.len());
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Ok,
                    http_status: Some(200),
                    error: None,
                    body: Some(body),
                })
            }
            Ok(Err(error)) => {
                let error = format!("get body read failed: {error}");
                recorder.finish(
                    record,
                    OperationOutcome::Unknown,
                    Some(200),
                    Some(error.clone()),
                )?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Unknown,
                    http_status: Some(200),
                    error: Some(error),
                    body: None,
                })
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    Some(200),
                    Some("get body read timed out".to_string()),
                )?;
                Ok(GetObjectResult {
                    outcome: OperationOutcome::Timeout,
                    http_status: Some(200),
                    error: Some("get body read timed out".to_string()),
                    body: None,
                })
            }
        }
    }

    pub async fn put_and_verify_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<VerifiedWriteResult> {
        let write_outcome = self.put_object(object, recorder).await?;
        if write_outcome != OperationOutcome::Ok {
            return Ok(VerifiedWriteResult {
                write_outcome,
                verify_get_outcome: None,
                verified: false,
            });
        }

        let get = self.get_object_result(&object.spec.key, recorder).await?;
        let verified = get
            .body
            .as_deref()
            .is_some_and(|body| object.spec.matches_body(body));
        Ok(VerifiedWriteResult {
            write_outcome,
            verify_get_outcome: Some(get.outcome),
            verified,
        })
    }

    pub async fn delete_object(&self, key: &str, recorder: &Recorder) -> Result<OperationOutcome> {
        Ok(self.delete_object_record(key, recorder).await?.outcome)
    }

    pub(crate) async fn delete_object_record(
        &self,
        key: &str,
        recorder: &Recorder,
    ) -> Result<OperationRecord> {
        Ok(self.delete_object_result(key, recorder).await?.record)
    }

    /// Returns no trigger candidate when a successful DELETE does not prove it
    /// created a versioned delete marker. Failed attempts are returned so the
    /// acknowledgement policy can preserve their exact outcome.
    pub(crate) async fn delete_marker_record(
        &self,
        key: &str,
        recorder: &Recorder,
    ) -> Result<Option<OperationRecord>> {
        let result = self.delete_object_result(key, recorder).await?;
        if result.record.outcome == OperationOutcome::Ok && result.is_delete_marker != Some(true) {
            return Ok(None);
        }
        Ok(Some(result.record))
    }

    async fn delete_object_result(&self, key: &str, recorder: &Recorder) -> Result<RecordedDelete> {
        let record = recorder.begin(
            OperationKind::Delete,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        let result = self
            .mutation_request(
                self.client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .await;

        match result {
            Ok(Ok(output)) => {
                let mut record = record;
                record.version_id = output.version_id().map(str::to_string);
                Ok(RecordedDelete {
                    record: recorder.finish(record, OperationOutcome::Ok, Some(204), None)?,
                    is_delete_marker: output.delete_marker(),
                })
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                Ok(RecordedDelete {
                    record: recorder.finish(
                        record,
                        outcome,
                        sdk_error_status(&error),
                        Some(format!("delete object failed: {error}")),
                    )?,
                    is_delete_marker: None,
                })
            }
            Err(_) => Ok(RecordedDelete {
                record: recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("delete object timed out".to_string()),
                )?,
                is_delete_marker: None,
            }),
        }
    }

    pub async fn delete_and_verify_absent(
        &self,
        key: &str,
        recorder: &Recorder,
    ) -> Result<(OperationOutcome, Option<OperationOutcome>)> {
        let delete_outcome = self.delete_object(key, recorder).await?;
        if delete_outcome != OperationOutcome::Ok {
            return Ok((delete_outcome, None));
        }
        let get = self.get_object_result(key, recorder).await?;
        Ok((delete_outcome, Some(get.outcome)))
    }

    pub async fn complete_multipart_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<OperationOutcome> {
        Ok(self
            .complete_multipart_object_record(object, recorder)
            .await?
            .map_or(OperationOutcome::Unknown, |record| record.outcome))
    }

    /// Completes one multipart object and returns its completion record. A
    /// missing record means setup failed before CompleteMultipartUpload was
    /// attempted, so callers must not treat it as an acknowledged mutation.
    pub(crate) async fn complete_multipart_object_record(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<Option<OperationRecord>> {
        let Some(staged) = self.try_stage_multipart_object(object, recorder).await? else {
            return Ok(None);
        };
        let result = self
            .complete_staged_multipart_object_record(&staged, recorder)
            .await;
        if self.mutation_deadline.is_some()
            && !matches!(&result, Ok(record) if record.outcome == OperationOutcome::Ok)
        {
            self.abort_staged_multipart_object(&staged, recorder)
                .await?;
        }
        result.map(Some)
    }

    pub(crate) async fn stage_multipart_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<StagedMultipartUpload> {
        self.try_stage_multipart_object(object, recorder)
            .await?
            .context("multipart upload could not be staged before fault activation")
    }

    async fn try_stage_multipart_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<Option<StagedMultipartUpload>> {
        let Some(upload_id) = self
            .create_multipart_upload(&object.spec.key, recorder)
            .await?
        else {
            return Ok(None);
        };
        let mut staged = StagedMultipartUpload {
            spec: object.spec.clone(),
            upload_id,
            completed_parts: Vec::new(),
        };
        let mut cancellation_cleanup =
            StagedMultipartCleanupGuard::new(self.clone(), recorder.clone(), staged.clone());
        let result: Result<bool> = async {
            for (index, chunk) in object.body.chunks(5 * 1024 * 1024).enumerate() {
                let Some(part) = self
                    .upload_part(
                        &staged.spec.key,
                        &staged.upload_id,
                        (index + 1) as i32,
                        chunk,
                        recorder,
                    )
                    .await?
                else {
                    return Ok(false);
                };
                staged.completed_parts.push(part);
            }
            Ok(true)
        }
        .await;
        if !matches!(result, Ok(true)) {
            let cleanup = self.abort_staged_multipart_object(&staged, recorder).await;
            // The guard remains armed while the async abort is in flight, so
            // cancellation retries it. A completed attempt is recorded and
            // reported exactly once, even when the server rejects cleanup.
            cancellation_cleanup.disarm();
            cleanup?;
            return result.map(|_| None);
        }
        cancellation_cleanup.disarm();
        Ok(Some(staged))
    }

    pub(crate) async fn complete_staged_multipart_object(
        &self,
        staged: &StagedMultipartUpload,
        recorder: &Recorder,
    ) -> Result<OperationOutcome> {
        Ok(self
            .complete_staged_multipart_object_record(staged, recorder)
            .await?
            .outcome)
    }

    pub(crate) async fn complete_staged_multipart_object_record(
        &self,
        staged: &StagedMultipartUpload,
        recorder: &Recorder,
    ) -> Result<OperationRecord> {
        let record = recorder.begin(
            OperationKind::CompleteMultipartUpload,
            self.bucket.clone(),
            Some(staged.spec.key.clone()),
            Some(staged.spec.sha256.clone()),
            Some(staged.spec.size_bytes),
        );
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(staged.completed_parts.clone()))
            .build();
        let result = self
            .mutation_request(
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(&staged.spec.key)
                    .upload_id(&staged.upload_id)
                    .multipart_upload(upload)
                    .send(),
            )
            .await;
        match result {
            Ok(Ok(output)) => {
                let mut record = record;
                record.version_id = output.version_id().map(str::to_string);
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)
            }
            Ok(Err(error)) => recorder.finish(
                record,
                classify_sdk_error(&error),
                sdk_error_status(&error),
                Some(format!("complete multipart upload failed: {error}")),
            ),
            Err(_) => recorder.finish(
                record,
                OperationOutcome::Timeout,
                None,
                Some("complete multipart upload timed out".to_string()),
            ),
        }
    }

    pub(crate) async fn abort_staged_multipart_object(
        &self,
        staged: &StagedMultipartUpload,
        recorder: &Recorder,
    ) -> Result<()> {
        // Cleanup keeps its request timeout even after a quiet mutation expires.
        let outcome = self
            .abort_multipart_upload(&staged.spec.key, &staged.upload_id, recorder)
            .await
            .with_context(|| {
                format!(
                    "multipart cleanup for key {} upload {}",
                    staged.spec.key, staged.upload_id
                )
            })?;
        ensure!(
            matches!(outcome, OperationOutcome::Ok | OperationOutcome::NotFound),
            "multipart cleanup for key {} upload {} ended with {:?}",
            staged.spec.key,
            staged.upload_id,
            outcome
        );
        Ok(())
    }

    pub async fn abort_multipart_object(
        &self,
        object: &PreparedObject,
        recorder: &Recorder,
    ) -> Result<OperationOutcome> {
        let Some(upload_id) = self
            .create_multipart_upload(&object.spec.key, recorder)
            .await?
        else {
            return Ok(OperationOutcome::Unknown);
        };
        self.abort_multipart_upload(&object.spec.key, &upload_id, recorder)
            .await
    }

    async fn create_multipart_upload(
        &self,
        key: &str,
        recorder: &Recorder,
    ) -> Result<Option<String>> {
        let record = recorder.begin(
            OperationKind::CreateMultipartUpload,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        let result = self
            .mutation_request(
                self.client
                    .create_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .await;

        match result {
            Ok(Ok(output)) => {
                let Some(upload_id) = output.upload_id().map(str::to_string) else {
                    recorder.finish(
                        record,
                        OperationOutcome::Unknown,
                        Some(200),
                        Some("create multipart upload omitted upload_id".to_string()),
                    )?;
                    return Ok(None);
                };
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(Some(upload_id))
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("create multipart upload failed: {error}")),
                )?;
                Ok(None)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("create multipart upload timed out".to_string()),
                )?;
                Ok(None)
            }
        }
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: &[u8],
        recorder: &Recorder,
    ) -> Result<Option<CompletedPart>> {
        let record = recorder.begin(
            OperationKind::UploadPart,
            self.bucket.clone(),
            Some(key.to_string()),
            Some(sha256_hex(body)),
            Some(body.len()),
        );
        let result = self
            .mutation_request(
                self.client
                    .upload_part()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .body(ByteStream::from(body.to_vec()))
                    .send(),
            )
            .await;

        match result {
            Ok(Ok(output)) => {
                let Some(e_tag) = output.e_tag().map(str::to_string) else {
                    recorder.finish(
                        record,
                        OperationOutcome::Unknown,
                        Some(200),
                        Some(format!("upload part {part_number} omitted ETag")),
                    )?;
                    return Ok(None);
                };
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(Some(
                    CompletedPart::builder()
                        .part_number(part_number)
                        .e_tag(e_tag)
                        .build(),
                ))
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("upload part {part_number} failed: {error}")),
                )?;
                Ok(None)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some(format!("upload part {part_number} timed out")),
                )?;
                Ok(None)
            }
        }
    }

    async fn abort_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        recorder: &Recorder,
    ) -> Result<OperationOutcome> {
        let record = recorder.begin(
            OperationKind::AbortMultipartUpload,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        let result = timeout(
            self.request_timeout,
            self.client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id)
                .send(),
        )
        .await;

        match result {
            Ok(Ok(_)) => {
                recorder.finish(record, OperationOutcome::Ok, Some(204), None)?;
                Ok(OperationOutcome::Ok)
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("abort multipart upload failed: {error}")),
                )?;
                Ok(outcome)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("abort multipart upload timed out".to_string()),
                )?;
                Ok(OperationOutcome::Timeout)
            }
        }
    }

    pub async fn head_object(&self, key: &str, recorder: &Recorder) -> Result<OperationOutcome> {
        let record = recorder.begin(
            OperationKind::Head,
            self.bucket.clone(),
            Some(key.to_string()),
            None,
            None,
        );
        let result = timeout(
            self.request_timeout,
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        )
        .await;

        match result {
            Ok(Ok(_)) => {
                recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
                Ok(OperationOutcome::Ok)
            }
            Ok(Err(error)) => {
                let outcome = classify_sdk_error(&error);
                recorder.finish(
                    record,
                    outcome,
                    sdk_error_status(&error),
                    Some(format!("head object failed: {error}")),
                )?;
                Ok(outcome)
            }
            Err(_) => {
                recorder.finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("head object timed out".to_string()),
                )?;
                Ok(OperationOutcome::Timeout)
            }
        }
    }

    pub async fn list_prefix(
        &self,
        prefix: &str,
        recorder: &Recorder,
    ) -> Result<Option<Vec<String>>> {
        let record = recorder.begin(
            OperationKind::List,
            self.bucket.clone(),
            Some(prefix.to_string()),
            None,
            None,
        );
        let mut keys = Vec::new();
        let mut continuation_token = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = continuation_token.as_deref() {
                request = request.continuation_token(token);
            }
            let response = timeout(self.request_timeout, request.send()).await;
            let output = match response {
                Ok(Ok(output)) => output,
                Ok(Err(error)) => {
                    let outcome = classify_sdk_error(&error);
                    recorder.finish(
                        record,
                        outcome,
                        sdk_error_status(&error),
                        Some(format!("list prefix failed: {error}")),
                    )?;
                    return Ok(None);
                }
                Err(_) => {
                    recorder.finish(
                        record,
                        OperationOutcome::Timeout,
                        None,
                        Some("list prefix timed out".to_string()),
                    )?;
                    return Ok(None);
                }
            };
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(|object| object.key().map(str::to_string)),
            );
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            continuation_token = output.next_continuation_token().map(str::to_string);
            if continuation_token.is_none() {
                recorder.finish(
                    record,
                    OperationOutcome::Unknown,
                    Some(200),
                    Some("truncated LIST response omitted continuation token".to_string()),
                )?;
                return Ok(None);
            }
        }

        let mut record = record;
        record.size_bytes = Some(keys.len());
        record.listed_keys = Some(keys.clone());
        recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
        Ok(Some(keys))
    }

    pub async fn list_object_versions(
        &self,
        prefix: &str,
        recorder: &Recorder,
    ) -> Result<Option<Vec<ObjectVersionEntry>>> {
        let record = recorder.begin(
            OperationKind::ListVersions,
            self.bucket.clone(),
            Some(prefix.to_string()),
            None,
            None,
        );
        let mut entries = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut version_id_marker: Option<String> = None;
        loop {
            let request = self
                .client
                .list_object_versions()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_key_marker(key_marker.clone())
                .set_version_id_marker(version_id_marker.clone());
            let response = timeout(self.request_timeout, request.send()).await;
            let output = match response {
                Ok(Ok(output)) => output,
                Ok(Err(error)) => {
                    let outcome = classify_sdk_error(&error);
                    recorder.finish(
                        record,
                        outcome,
                        sdk_error_status(&error),
                        Some(format!("list object versions failed: {error}")),
                    )?;
                    return Ok(None);
                }
                Err(_) => {
                    recorder.finish(
                        record,
                        OperationOutcome::Timeout,
                        None,
                        Some("list object versions timed out".to_string()),
                    )?;
                    return Ok(None);
                }
            };
            entries.extend(output.versions().iter().filter_map(|version| {
                Some(ObjectVersionEntry {
                    key: version.key().map(str::to_string)?,
                    version_id: version.version_id().map(str::to_string),
                    is_latest: version.is_latest().unwrap_or(false),
                    is_delete_marker: false,
                })
            }));
            entries.extend(output.delete_markers().iter().filter_map(|marker| {
                Some(ObjectVersionEntry {
                    key: marker.key().map(str::to_string)?,
                    version_id: marker.version_id().map(str::to_string),
                    is_latest: marker.is_latest().unwrap_or(false),
                    is_delete_marker: true,
                })
            }));
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            key_marker = output.next_key_marker().map(str::to_string);
            version_id_marker = output.next_version_id_marker().map(str::to_string);
            if key_marker.is_none() && version_id_marker.is_none() {
                recorder.finish(
                    record,
                    OperationOutcome::Unknown,
                    Some(200),
                    Some("truncated ListObjectVersions response omitted markers".to_string()),
                )?;
                return Ok(None);
            }
        }

        let mut record = record;
        record.size_bytes = Some(entries.len());
        recorder.finish(record, OperationOutcome::Ok, Some(200), None)?;
        Ok(Some(entries))
    }
}

pub fn sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

pub async fn wait_for_s3_endpoint(endpoint: &str, timeout_duration: Duration) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build S3 readiness HTTP client")?;
    let start = std::time::Instant::now();

    loop {
        if client.get(endpoint).send().await.is_ok() {
            return Ok(());
        }
        if start.elapsed() >= timeout_duration {
            anyhow::bail!("timed out waiting for S3 endpoint {endpoint}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub(crate) fn seeded_bytes(seed: u64, index: usize, size_bytes: usize) -> Vec<u8> {
    let mut generator = SplitMix64::new(seed ^ (index as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93));
    let mut body = vec![0; size_bytes];
    for chunk in body.chunks_mut(8) {
        let bytes = generator.next_u64().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    body
}

fn shuffle_sizes(sizes: &mut [usize], seed: u64) {
    let mut generator = SplitMix64::new(seed ^ 0xA076_1D64_78BD_642F);
    for index in (1..sizes.len()).rev() {
        let swap_with = (generator.next_u64() % (index as u64 + 1)) as usize;
        sizes.swap(index, swap_with);
    }
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

fn classify_sdk_error<E>(error: &SdkError<E>) -> OperationOutcome {
    match error {
        SdkError::TimeoutError(_) => OperationOutcome::Timeout,
        SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => OperationOutcome::Unknown,
        SdkError::ServiceError(context) if context.raw().status().as_u16() == 404 => {
            OperationOutcome::NotFound
        }
        SdkError::ConstructionFailure(_) | SdkError::ServiceError(_) => OperationOutcome::Failed,
        _ => OperationOutcome::Unknown,
    }
}

fn sdk_error_status<E>(error: &SdkError<E>) -> Option<u16> {
    match error {
        SdkError::ServiceError(context) => Some(context.raw().status().as_u16()),
        SdkError::ResponseError(context) => Some(context.raw().status().as_u16()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ObjectSpec, SplitMix64, StagedMultipartCleanupGuard, WorkloadHotspot, WorkloadOperation,
        WorkloadOperationMix, WorkloadPayloadClass, WorkloadPayloadDistribution, WorkloadPlan,
        sha256_hex,
    };

    #[tokio::test]
    async fn quiet_deadline_does_not_poll_another_request_or_change_the_shared_client() {
        let client = super::S3WorkloadClient::new(
            "http://127.0.0.1:1",
            "bucket",
            "test-access",
            "test-secret",
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("client");
        let original_retry = client.client.config().retry_config().cloned();
        let quiet = client.for_quiet_mutation(tokio::time::Instant::now());
        let polled = std::cell::Cell::new(false);
        let result = quiet
            .mutation_request(async {
                polled.set(true);
            })
            .await;

        assert!(result.is_err());
        assert!(!polled.get());
        assert!(client.mutation_deadline.is_none());
        assert_eq!(
            client.client.config().retry_config(),
            original_retry.as_ref()
        );
        assert_eq!(
            quiet
                .client
                .config()
                .retry_config()
                .expect("quiet retries")
                .max_attempts(),
            1
        );
    }

    #[test]
    fn staged_multipart_cleanup_guard_runs_on_cancellation_and_can_be_disarmed() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let calls = Arc::new(AtomicUsize::new(0));
        {
            let calls = Arc::clone(&calls);
            let _guard = StagedMultipartCleanupGuard::from_cleanup(move || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        {
            let calls = Arc::clone(&calls);
            let mut guard = StagedMultipartCleanupGuard::from_cleanup(move || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            guard.disarm();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn seeded_objects_have_stable_keys_sizes_and_hashes() {
        let object = ObjectSpec::prepare_seeded("run-1", 7, 4096, 42);
        let same = ObjectSpec::prepare_seeded("run-1", 7, 4096, 42);

        assert_eq!(ObjectSpec::key_prefix("run-1"), "fault-test/run-1/");
        assert_eq!(object.spec.key, "fault-test/run-1/object-000007");
        assert_eq!(object.spec.size_bytes, 4096);
        assert_eq!(object.spec.sha256, same.spec.sha256);
        assert_eq!(object.spec.sha256, sha256_hex(&same.body));
        assert!(object.spec.matches_body(&same.body));
        assert_ne!(
            object.spec.sha256,
            ObjectSpec::prepare_seeded("run-1", 7, 4096, 43).spec.sha256
        );

        let mut corrupted = same.body.clone();
        corrupted[0] ^= 1;
        assert!(!object.spec.matches_body(&corrupted));
        assert!(!object.spec.matches_body(&same.body[..same.body.len() - 1]));
    }

    #[test]
    fn workload_plan_is_weighted_shuffled_and_reproducible() {
        let plan = WorkloadPlan::seeded(42, 40000, 80);
        let same = WorkloadPlan::seeded(42, 40000, 80);
        let different = WorkloadPlan::seeded(43, 40000, 80);

        assert_eq!(plan, same);
        assert_ne!(plan.sizes, different.sizes);
        assert_eq!(
            plan.size_distribution
                .iter()
                .map(|class| (class.size_bytes, class.object_count))
                .collect::<Vec<_>>(),
            vec![
                (4 * 1024, 34000),
                (16 * 1024, 4000),
                (8 * 1024 * 1024, 1600),
                (16 * 1024 * 1024, 400),
            ]
        );
        assert_eq!(plan.total_payload_bytes, 20_337_459_200);
        assert_eq!(plan.concurrency, 80);
        assert_eq!(plan.operation_mix, WorkloadOperationMix::default());
        assert_eq!(
            (0..6)
                .map(|offset| plan.operation_mix.operation_at(offset))
                .collect::<Vec<_>>(),
            vec![
                WorkloadOperation::Put,
                WorkloadOperation::Overwrite,
                WorkloadOperation::Get,
                WorkloadOperation::List,
                WorkloadOperation::Delete,
                WorkloadOperation::Multipart,
            ]
        );
    }

    #[test]
    fn workload_operation_mix_is_weighted_and_validated() {
        let mix = WorkloadOperationMix {
            put: 2,
            overwrite: 1,
            get: 1,
            list: 1,
            delete: 1,
            multipart: 1,
        };

        assert_eq!(
            (0..7)
                .map(|offset| mix.operation_at(offset))
                .collect::<Vec<_>>(),
            vec![
                WorkloadOperation::Put,
                WorkloadOperation::Put,
                WorkloadOperation::Overwrite,
                WorkloadOperation::Get,
                WorkloadOperation::List,
                WorkloadOperation::Delete,
                WorkloadOperation::Multipart,
            ]
        );

        assert!(
            WorkloadOperationMix {
                put: 0,
                ..WorkloadOperationMix::default()
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            WorkloadOperationMix {
                put: u32::MAX,
                overwrite: u32::MAX,
                get: u32::MAX,
                list: u32::MAX,
                delete: u32::MAX,
                multipart: u32::MAX,
            }
            .total_weight(),
            u64::from(u32::MAX) * 6
        );
        assert!(
            WorkloadPlan::seeded_with_mix(
                42,
                128,
                8,
                WorkloadOperationMix {
                    put: 0,
                    ..WorkloadOperationMix::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn workload_profile_applies_payload_distribution_and_hotspot() {
        let plan = WorkloadPlan::seeded_with_profile(
            42,
            20,
            4,
            WorkloadOperationMix::default(),
            Some(WorkloadPayloadDistribution {
                classes: vec![
                    WorkloadPayloadClass {
                        size_bytes: 1024,
                        weight: 1,
                    },
                    WorkloadPayloadClass {
                        size_bytes: 4096,
                        weight: 3,
                    },
                ],
            }),
            Some(WorkloadHotspot {
                object_percent: 10,
                operation_percent: 100,
            }),
        )
        .expect("workload profile");

        assert_eq!(plan.size_distribution[0].object_count, 5);
        assert_eq!(plan.size_distribution[1].object_count, 15);
        assert_eq!(plan.total_payload_bytes, 5 * 1024 + 15 * 4096);
        for offset in 0..32 {
            assert!(
                plan.existing_object_offset(offset, 100) < 10,
                "100% hotspot operations should stay inside the hot set"
            );
        }
    }

    #[test]
    fn workload_hotspot_keeps_cold_operations_outside_hot_set() {
        let plan = WorkloadPlan::seeded_with_profile(
            42,
            100,
            4,
            WorkloadOperationMix::default(),
            None,
            Some(WorkloadHotspot {
                object_percent: 50,
                operation_percent: 50,
            }),
        )
        .expect("workload profile");

        for offset in 0..512 {
            let mut generator =
                SplitMix64::new(plan.seed ^ (offset as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
            let use_hotspot = generator.next_u64() % 100 < 50;
            let selected = plan.existing_object_offset(offset, 100);

            if use_hotspot {
                assert!(selected < 50, "hot operation should stay inside hot set");
            } else {
                assert!(selected >= 50, "cold operation should stay outside hot set");
            }
        }
    }

    #[test]
    fn workload_profile_rejects_unsafe_payload_and_hotspot_values() {
        let invalid_payload = WorkloadPayloadDistribution {
            classes: vec![WorkloadPayloadClass {
                size_bytes: 0,
                weight: 1,
            }],
        };
        assert!(invalid_payload.validate().is_err());

        assert!(
            WorkloadHotspot {
                object_percent: 0,
                operation_percent: 100,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn workload_plan_deserialization_rehydrates_runtime_sizes() {
        let plan = WorkloadPlan::seeded(42, 128, 8);
        let encoded = serde_json::to_string(&plan).expect("workload plan json");
        let decoded =
            serde_json::from_str::<WorkloadPlan>(&encoded).expect("decoded workload plan");

        assert_eq!(decoded, plan);
        assert_eq!(decoded.size_at(0), plan.size_at(0));
        assert_eq!(decoded.size_at(127), plan.size_at(127));
    }

    #[test]
    fn workload_plan_deserialization_rejects_invalid_distribution() {
        let plan = WorkloadPlan::seeded(42, 128, 8);
        let mut value = serde_json::to_value(&plan).expect("workload plan json");
        value["object_count"] = serde_json::json!(129);

        let result = serde_json::from_value::<WorkloadPlan>(value);

        assert!(result.is_err());
    }

    #[test]
    fn directory_marker_is_zero_byte_with_trailing_slash_key() {
        let object = ObjectSpec::prepare_directory_marker("run-1", 7, 42);

        assert!(object.spec.is_directory_marker());
        assert_eq!(object.spec.key, "fault-test/run-1/dir-000007/");
        assert_eq!(object.spec.size_bytes, 0);
        assert!(object.body.is_empty());
        // The recorded sha must be the empty-body sha, and matches_body must
        // accept the zero-length GET body the prefill verifier passes in.
        assert_eq!(object.spec.sha256, sha256_hex(&[]));
        assert!(object.spec.matches_body(&[]));
        assert!(!object.spec.matches_body(b"x"));

        // A plain object of the same index is not a directory marker.
        assert!(
            !ObjectSpec::prepare_seeded("run-1", 7, 16, 42)
                .spec
                .is_directory_marker()
        );
    }

    #[test]
    fn overwriting_a_directory_marker_stays_zero_byte_with_the_same_key() {
        let marker = ObjectSpec::prepare_directory_marker("run-1", 7, 42);
        let overwrite = marker.spec.prepare_overwrite(3);

        assert_eq!(overwrite.spec.key, marker.spec.key);
        assert_eq!(overwrite.spec.size_bytes, 0);
        assert!(overwrite.body.is_empty());
        assert!(overwrite.spec.is_directory_marker());
    }
}

pub(in crate::fault) mod execution;
