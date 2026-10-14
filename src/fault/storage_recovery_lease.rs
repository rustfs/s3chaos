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

//! Kubernetes Lease adapter for exclusive storage-recovery ownership.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::{
    api::coordination::v1::{Lease, LeaseSpec},
    apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta},
    chrono::{TimeZone, Utc},
};
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, PostParams, Preconditions},
};
use serde::{Deserialize, Serialize};

use crate::fault::storage_recovery::{StorageRecoveryCase, StorageVolumeIdentity};
use crate::fault::storage_recovery_runtime::{
    HostGenerationIdentity, KubernetesLeaseProof, OwnedStorageContext,
    StorageRecoveryHostOperation, StorageRecoveryOperationReceipt, storage_lease_name,
};

const SCOPE_ANNOTATION: &str = "s3chaos.rustfs.com/storage-scope-sha256";
const MIN_LEASE_DURATION_SECONDS: u64 = 5;
const MAX_LEASE_DURATION_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageRecoveryCleanupProof {
    AbortedBeforeMutation {
        observed_at_ms: u64,
    },
    BitrotRestored {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotAlreadyRepaired {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotVerifiedSuperseded {
        verification_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotQuarantined {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    StaleDiskReattached {
        reattach_receipt: Box<StorageRecoveryOperationReceipt>,
        reattach_context: Box<OwnedStorageContext>,
        post_reattach_generation: Box<HostGenerationIdentity>,
        observed_at_ms: u64,
    },
    FreshVolumeCommitted {
        prepare_receipt: Box<StorageRecoveryOperationReceipt>,
        replacement_volume: Box<StorageVolumeIdentity>,
        old_device_absence_sha256: String,
        observed_at_ms: u64,
    },
}

impl StorageRecoveryCleanupProof {
    pub fn validate_for(&self, context: &OwnedStorageContext) -> Result<()> {
        match self {
            Self::AbortedBeforeMutation { observed_at_ms } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement
                            | StorageRecoveryCase::FreshVolumeReplacementAdminDeep
                            | StorageRecoveryCase::FreshVolumeReplacementPartitionDuringHeal
                            | StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                            | StorageRecoveryCase::MetadataShardCorruptionAdminDeep
                            | StorageRecoveryCase::StaleDiskReturn
                    ) && *observed_at_ms
                        >= context.exclusive_access.kubernetes_lease.acquired_at_ms,
                    "pre-mutation abort proof is not a supported storage Lease-generation proof"
                );
                Ok(())
            }
            Self::BitrotRestored { restore_receipt }
            | Self::BitrotAlreadyRepaired { restore_receipt }
            | Self::BitrotQuarantined {
                restore_receipt, ..
            } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                            | StorageRecoveryCase::MetadataShardCorruptionAdminDeep
                    ),
                    "bitrot cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    restore_receipt,
                    |operation| {
                        matches!(operation, StorageRecoveryHostOperation::RestoreShard { .. })
                    },
                    "shard restoration",
                )?;
                let response: serde_json::Value =
                    serde_json::from_str(&restore_receipt.response_body)
                        .context("decode shard cleanup response")?;
                let expected = match self {
                    Self::BitrotRestored { .. } => "restored",
                    Self::BitrotAlreadyRepaired { .. } => "already-repaired",
                    Self::BitrotQuarantined { .. } => "quarantined",
                    _ => unreachable!("matched a restore-receipt bitrot cleanup"),
                };
                ensure!(
                    response.get("outcome").and_then(serde_json::Value::as_str) == Some(expected),
                    "shard cleanup response does not prove the declared terminal state"
                );
                if matches!(self, Self::BitrotQuarantined { .. }) {
                    bail!(
                        "quarantined shard is durable evidence, not successful cleanup; explicit repair acknowledgement is required"
                    )
                }
                Ok(())
            }
            Self::BitrotVerifiedSuperseded {
                verification_receipt,
            } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                            | StorageRecoveryCase::MetadataShardCorruptionAdminDeep
                    ),
                    "bitrot superseded cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    verification_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::VerifySupersededShard { .. }
                        )
                    },
                    "superseded-shard verification",
                )?;
                let response: serde_json::Value =
                    serde_json::from_str(&verification_receipt.response_body)
                        .context("decode superseded-shard cleanup response")?;
                ensure!(
                    response.get("outcome").and_then(serde_json::Value::as_str)
                        == Some("verified-superseded"),
                    "superseded-shard cleanup response has the wrong terminal state"
                );
                Ok(())
            }
            Self::StaleDiskReattached {
                reattach_receipt,
                reattach_context,
                post_reattach_generation,
                observed_at_ms,
            } => {
                ensure!(
                    context.case == StorageRecoveryCase::StaleDiskReturn,
                    "stale-disk cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    reattach_context,
                    reattach_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
                        )
                    },
                    "device-mapper reattach",
                )?;
                ensure!(
                    reattach_context.identity == context.identity
                        && reattach_context.case == context.case
                        && reattach_context.attempt_id == context.attempt_id
                        && reattach_context.cluster_context == context.cluster_context
                        && reattach_context.tenant_uid == context.tenant_uid
                        && reattach_context.scope_sha256 == context.scope_sha256
                        && crate::fault::storage_recovery_runtime::same_storage_volume_generation(
                            &reattach_context.volume,
                            &context.volume,
                        )
                        && reattach_context.resource_versions == context.resource_versions
                        && reattach_context.host_generation == context.host_generation
                        && reattach_context.exclusive_access.host_flock
                            == context.exclusive_access.host_flock
                        && reattach_context.exclusive_access.kubernetes_lease.uid
                            == context.exclusive_access.kubernetes_lease.uid
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .acquired_at_ms
                            == context.exclusive_access.kubernetes_lease.acquired_at_ms
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .holder_identity
                            == context.exclusive_access.kubernetes_lease.holder_identity
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .renew_at_ms
                            <= context.exclusive_access.kubernetes_lease.renew_at_ms
                        && post_reattach_generation.as_ref() == &context.host_generation
                        && *observed_at_ms >= reattach_receipt.completed_at_ms,
                    "stale-disk cleanup does not prove the expected reattached generation"
                );
                Ok(())
            }
            Self::FreshVolumeCommitted {
                prepare_receipt,
                replacement_volume,
                old_device_absence_sha256,
                observed_at_ms,
            } => {
                ensure!(
                    context.case.is_fresh_volume_replacement(),
                    "fresh-volume cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    prepare_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::PrepareFreshVolume { .. }
                        )
                    },
                    "fresh-volume preparation",
                )?;
                replacement_volume.validate()?;
                context
                    .volume
                    .validate_replacement_generation(replacement_volume)?;
                let StorageRecoveryHostOperation::PrepareFreshVolume {
                    replacement_persistent_volume,
                    replacement_persistent_volume_claim,
                } = &prepare_receipt.operation
                else {
                    unreachable!("operation was checked above")
                };
                validate_sha256(old_device_absence_sha256)?;
                ensure!(
                    replacement_volume.persistent_volume == *replacement_persistent_volume
                        && replacement_volume.persistent_volume_claim
                            == *replacement_persistent_volume_claim
                        && *observed_at_ms >= prepare_receipt.completed_at_ms,
                    "fresh-volume cleanup does not prove replacement ownership and old-device absence"
                );
                Ok(())
            }
        }
    }

    pub(crate) fn completed_at_ms(&self) -> u64 {
        match self {
            Self::AbortedBeforeMutation { observed_at_ms } => *observed_at_ms,
            Self::BitrotRestored { restore_receipt }
            | Self::BitrotAlreadyRepaired { restore_receipt }
            | Self::BitrotQuarantined {
                restore_receipt, ..
            } => restore_receipt.completed_at_ms,
            Self::BitrotVerifiedSuperseded {
                verification_receipt,
            } => verification_receipt.completed_at_ms,
            Self::StaleDiskReattached { observed_at_ms, .. }
            | Self::FreshVolumeCommitted { observed_at_ms, .. } => *observed_at_ms,
        }
    }
}

fn validate_receipt_operation(
    context: &OwnedStorageContext,
    receipt: &StorageRecoveryOperationReceipt,
    expected: impl FnOnce(&StorageRecoveryHostOperation) -> bool,
    label: &str,
) -> Result<()> {
    receipt.validate_for(context, &receipt.operation)?;
    ensure!(
        expected(&receipt.operation),
        "cleanup proof is not a {label} receipt"
    );
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "cleanup proof digest is not SHA-256 hex"
    );
    Ok(())
}

pub struct KubernetesStorageLeaseAdapter {
    api: Api<Lease>,
    name: String,
    scope_sha256: String,
    holder_identity: String,
    duration_seconds: i32,
}

impl KubernetesStorageLeaseAdapter {
    pub fn new(
        client: Client,
        namespace: &str,
        scope_sha256: &str,
        run_id: &str,
        attempt_id: &str,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            !namespace.trim().is_empty()
                && !run_id.trim().is_empty()
                && !attempt_id.trim().is_empty(),
            "storage-recovery Lease identity is empty"
        );
        let holder_identity = format!("{run_id}/{attempt_id}");
        ensure!(
            holder_identity.len() <= 128
                && holder_identity
                    .chars()
                    .all(|character| !character.is_control() && !character.is_whitespace()),
            "storage-recovery Lease holder identity is invalid"
        );
        let duration_seconds = duration.as_secs();
        ensure!(
            (MIN_LEASE_DURATION_SECONDS..=MAX_LEASE_DURATION_SECONDS).contains(&duration_seconds)
                && duration.subsec_nanos() == 0,
            "storage-recovery Lease duration must be an integral 5..=300 seconds"
        );
        Ok(Self {
            api: Api::namespaced(client, namespace),
            name: storage_lease_name(scope_sha256)?,
            scope_sha256: scope_sha256.to_string(),
            holder_identity,
            duration_seconds: i32::try_from(duration_seconds)?,
        })
    }

    pub async fn acquire(&self) -> Result<KubernetesLeaseProof> {
        for _ in 0..3 {
            let now_ms = now_ms()?;
            let Some(existing) = self
                .api
                .get_opt(&self.name)
                .await
                .context("read storage-recovery Kubernetes Lease")?
            else {
                let lease = self.lease(None, now_ms, now_ms, 0)?;
                match self.api.create(&PostParams::default(), &lease).await {
                    Ok(created) => return self.proof(&created),
                    Err(kube::Error::Api(response)) if response.code == 409 => continue,
                    Err(error) => {
                        return Err(error).context("create storage-recovery Kubernetes Lease");
                    }
                }
            };
            let decision =
                acquisition_decision(&existing, &self.scope_sha256, &self.holder_identity, now_ms)?;
            let (acquired_at_ms, transitions) = match decision {
                AcquisitionDecision::Renew {
                    acquired_at_ms,
                    transitions,
                } => (acquired_at_ms, transitions),
                AcquisitionDecision::TakeOver { transitions } => (now_ms, transitions),
                AcquisitionDecision::Contended {
                    holder,
                    expires_at_ms,
                } => {
                    bail!(
                        "storage-recovery Kubernetes Lease is held by {holder:?} until {expires_at_ms}"
                    )
                }
            };
            let lease = self.lease(
                existing.metadata.resource_version.clone(),
                acquired_at_ms,
                now_ms,
                transitions,
            )?;
            match self
                .api
                .replace(&self.name, &PostParams::default(), &lease)
                .await
            {
                Ok(replaced) => return self.proof(&replaced),
                Err(kube::Error::Api(response)) if response.code == 409 => continue,
                Err(error) => {
                    return Err(error).context("replace storage-recovery Kubernetes Lease");
                }
            }
        }
        bail!("storage-recovery Kubernetes Lease changed during three acquisition attempts")
    }

    pub async fn renew(&self, proof: &KubernetesLeaseProof) -> Result<KubernetesLeaseProof> {
        self.renew_inner(proof, false).await
    }

    pub async fn renew_for_cleanup(
        &self,
        proof: &KubernetesLeaseProof,
    ) -> Result<KubernetesLeaseProof> {
        self.renew_inner(proof, true).await
    }

    async fn renew_inner(
        &self,
        proof: &KubernetesLeaseProof,
        allow_expired_owned_generation: bool,
    ) -> Result<KubernetesLeaseProof> {
        self.validate_proof_identity(proof)?;
        let mut renewal_base = proof.clone();
        for _ in 0..3 {
            let existing = self
                .api
                .get(&self.name)
                .await
                .context("read storage-recovery Kubernetes Lease for renewal")?;
            let observed_at_ms = now_ms()?;
            let existing_proof = self.proof(&existing)?;
            if existing_proof.resource_version != renewal_base.resource_version {
                validate_advanced_owned_renewal(
                    &renewal_base,
                    &existing_proof,
                    observed_at_ms,
                    allow_expired_owned_generation,
                )?;
                if observed_at_ms < existing_proof.expires_at_ms {
                    return Ok(existing_proof);
                }
                renewal_base = existing_proof;
            } else {
                ensure!(
                    existing_proof == renewal_base,
                    "storage-recovery Kubernetes Lease generation drifted before renewal"
                );
            }
            ensure!(
                allow_expired_owned_generation || observed_at_ms < renewal_base.expires_at_ms,
                "storage-recovery Kubernetes Lease expired before renewal"
            );
            let decision = acquisition_decision(
                &existing,
                &self.scope_sha256,
                &self.holder_identity,
                observed_at_ms,
            )?;
            let AcquisitionDecision::Renew {
                acquired_at_ms,
                transitions,
            } = decision
            else {
                bail!("storage-recovery Kubernetes Lease is no longer renewable by this holder")
            };
            let replacement = self.lease(
                existing.metadata.resource_version,
                acquired_at_ms,
                observed_at_ms.max(
                    renewal_base
                        .renew_at_ms
                        .checked_add(1)
                        .context("storage-recovery Lease renewal timestamp overflow")?,
                ),
                transitions,
            )?;
            match self
                .api
                .replace(&self.name, &PostParams::default(), &replacement)
                .await
            {
                Ok(renewed) => {
                    let renewed_proof = self.proof(&renewed)?;
                    let returned_at_ms = now_ms()?;
                    if returned_at_ms < renewed_proof.expires_at_ms {
                        return Ok(renewed_proof);
                    }
                    ensure!(
                        allow_expired_owned_generation,
                        "storage-recovery Kubernetes Lease expired while renewal completed"
                    );
                    renewal_base = renewed_proof;
                }
                Err(first_error) => {
                    let current = self.api.get(&self.name).await.with_context(|| {
                        format!(
                            "reconcile storage-recovery Lease renewal after first error: {first_error}"
                        )
                    })?;
                    let current_proof = self.proof(&current)?;
                    let reconciled_at_ms = now_ms()?;
                    validate_advanced_owned_renewal(
                        &renewal_base,
                        &current_proof,
                        reconciled_at_ms,
                        allow_expired_owned_generation,
                    )
                    .with_context(|| {
                        format!(
                            "storage-recovery Lease renewal failed before reconciliation: {first_error}"
                        )
                    })?;
                    if reconciled_at_ms < current_proof.expires_at_ms {
                        return Ok(current_proof);
                    }
                    renewal_base = current_proof;
                }
            }
        }
        bail!(
            "storage-recovery Kubernetes Lease did not produce an active generation in three renewal attempts"
        )
    }

    pub async fn release(
        &self,
        context: &OwnedStorageContext,
        proof: &KubernetesLeaseProof,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        context.validate()?;
        cleanup.validate_for(context)?;
        self.validate_proof_identity(proof)?;
        ensure!(
            context.scope_sha256 == self.scope_sha256
                && context.exclusive_access.kubernetes_lease == *proof
                && cleanup.completed_at_ms() >= proof.acquired_at_ms,
            "storage-recovery cleanup proof is not bound to this Lease generation"
        );
        let current = self
            .api
            .get(&self.name)
            .await
            .context("re-read storage-recovery Kubernetes Lease before release")?;
        validate_current_lease(&current, proof, &self.scope_sha256, now_ms()?)?;
        self.api
            .delete(
                &self.name,
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        resource_version: Some(proof.resource_version.clone()),
                        uid: Some(proof.uid.clone()),
                    }),
                    ..DeleteParams::default()
                },
            )
            .await
            .context("release storage-recovery Kubernetes Lease")?;
        Ok(())
    }

    fn lease(
        &self,
        resource_version: Option<String>,
        acquired_at_ms: u64,
        renew_at_ms: u64,
        transitions: i32,
    ) -> Result<Lease> {
        Ok(Lease {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                resource_version,
                annotations: Some(BTreeMap::from([(
                    SCOPE_ANNOTATION.to_string(),
                    self.scope_sha256.clone(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(LeaseSpec {
                acquire_time: Some(micro_time(acquired_at_ms)?),
                holder_identity: Some(self.holder_identity.clone()),
                lease_duration_seconds: Some(self.duration_seconds),
                lease_transitions: Some(transitions),
                renew_time: Some(micro_time(renew_at_ms)?),
            }),
        })
    }

    fn proof(&self, lease: &Lease) -> Result<KubernetesLeaseProof> {
        validate_scope(lease, &self.scope_sha256)?;
        let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
        ensure!(
            spec.holder_identity.as_deref() == Some(self.holder_identity.as_str())
                && spec.lease_duration_seconds == Some(self.duration_seconds),
            "Kubernetes Lease response is not owned by the expected holder"
        );
        let acquired_at_ms = timestamp_ms(
            spec.acquire_time
                .as_ref()
                .context("Kubernetes Lease lacks acquireTime")?,
        )?;
        let renew_at_ms = timestamp_ms(
            spec.renew_time
                .as_ref()
                .context("Kubernetes Lease lacks renewTime")?,
        )?;
        Ok(KubernetesLeaseProof {
            name: self.name.clone(),
            uid: lease.uid().context("Kubernetes Lease response lacks UID")?,
            resource_version: lease
                .resource_version()
                .context("Kubernetes Lease response lacks resourceVersion")?,
            holder_identity: self.holder_identity.clone(),
            scope_sha256: self.scope_sha256.clone(),
            acquired_at_ms,
            renew_at_ms,
            expires_at_ms: expiry_ms(renew_at_ms, self.duration_seconds)?,
        })
    }

    fn validate_proof_identity(&self, proof: &KubernetesLeaseProof) -> Result<()> {
        ensure!(
            proof.name == self.name
                && proof.scope_sha256 == self.scope_sha256
                && proof.holder_identity == self.holder_identity
                && !proof.uid.trim().is_empty()
                && !proof.resource_version.trim().is_empty(),
            "storage-recovery Kubernetes Lease proof belongs to another owner or scope"
        );
        Ok(())
    }
}

fn validate_advanced_owned_renewal(
    previous: &KubernetesLeaseProof,
    current: &KubernetesLeaseProof,
    now_ms: u64,
    allow_expired_owned_generation: bool,
) -> Result<()> {
    ensure!(
        current.name == previous.name
            && current.uid == previous.uid
            && current.resource_version != previous.resource_version
            && current.holder_identity == previous.holder_identity
            && current.scope_sha256 == previous.scope_sha256
            && current.acquired_at_ms == previous.acquired_at_ms
            && current.renew_at_ms > previous.renew_at_ms
            && current.expires_at_ms > previous.expires_at_ms
            && (allow_expired_owned_generation || now_ms < current.expires_at_ms),
        "storage-recovery Kubernetes Lease does not prove an advanced renewal by this owner"
    );
    Ok(())
}

pub async fn require_current_lease(client: Client, context: &OwnedStorageContext) -> Result<()> {
    context.validate()?;
    let api: Api<Lease> = Api::namespaced(client, &context.volume.namespace);
    let lease = api
        .get(&context.exclusive_access.kubernetes_lease.name)
        .await
        .context("re-read storage-recovery Kubernetes Lease")?;
    validate_current_lease(
        &lease,
        &context.exclusive_access.kubernetes_lease,
        &context.scope_sha256,
        now_ms()?,
    )
}

pub async fn release_owned_lease(
    client: Client,
    context: &OwnedStorageContext,
    cleanup: &StorageRecoveryCleanupProof,
) -> Result<()> {
    context.validate()?;
    cleanup.validate_for(context)?;
    let proof = &context.exclusive_access.kubernetes_lease;
    let api: Api<Lease> = Api::namespaced(client, &context.volume.namespace);
    ensure!(
        cleanup.completed_at_ms() >= proof.acquired_at_ms,
        "storage-recovery cleanup predates the Lease generation"
    );
    let current = api
        .get(&proof.name)
        .await
        .context("re-read storage-recovery Kubernetes Lease before release")?;
    validate_current_lease(&current, proof, &context.scope_sha256, now_ms()?)?;
    let delete_params = DeleteParams {
        preconditions: Some(Preconditions {
            resource_version: Some(proof.resource_version.clone()),
            uid: Some(proof.uid.clone()),
        }),
        ..DeleteParams::default()
    };
    let first_error = match api.delete(&proof.name, &delete_params).await {
        Ok(_) => return Ok(()),
        Err(error) => error,
    };
    let current = match api.get(&proof.name).await {
        Ok(current) => current,
        Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
        Err(error) => {
            return Err(error).context(format!(
                "reconcile storage-recovery Lease release after first error: {first_error}"
            ));
        }
    };
    validate_current_lease(&current, proof, &context.scope_sha256, now_ms()?)?;
    match api.delete(&proof.name, &delete_params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Err(error) => Err(error).context(format!(
            "repeat storage-recovery Lease release after first error: {first_error}"
        )),
    }
}

pub async fn reconcile_owned_lease_release(
    client: Client,
    context: &OwnedStorageContext,
    cleanup: &StorageRecoveryCleanupProof,
) -> Result<()> {
    context.validate()?;
    cleanup.validate_for(context)?;
    let proof = &context.exclusive_access.kubernetes_lease;
    ensure!(
        cleanup.completed_at_ms() >= proof.acquired_at_ms,
        "storage-recovery cleanup predates the Lease generation"
    );
    let api: Api<Lease> = Api::namespaced(client, &context.volume.namespace);
    let current = match api.get(&proof.name).await {
        Ok(current) => current,
        Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
        Err(error) => {
            return Err(error).context("reconcile storage-recovery Kubernetes Lease release");
        }
    };
    validate_owned_lease_generation(&current, proof, &context.scope_sha256)?;
    match api
        .delete(
            &proof.name,
            &DeleteParams {
                preconditions: Some(Preconditions {
                    resource_version: Some(proof.resource_version.clone()),
                    uid: Some(proof.uid.clone()),
                }),
                ..DeleteParams::default()
            },
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Err(error) => Err(error).context("reconcile storage-recovery Kubernetes Lease deletion"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AcquisitionDecision {
    Renew {
        acquired_at_ms: u64,
        transitions: i32,
    },
    TakeOver {
        transitions: i32,
    },
    Contended {
        holder: String,
        expires_at_ms: u64,
    },
}

fn acquisition_decision(
    lease: &Lease,
    scope_sha256: &str,
    holder_identity: &str,
    now_ms: u64,
) -> Result<AcquisitionDecision> {
    validate_scope(lease, scope_sha256)?;
    let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
    let holder = spec
        .holder_identity
        .as_deref()
        .context("Kubernetes Lease lacks holderIdentity")?;
    let duration_seconds = spec
        .lease_duration_seconds
        .context("Kubernetes Lease lacks leaseDurationSeconds")?;
    ensure!(duration_seconds > 0, "Kubernetes Lease duration is invalid");
    let renew_at_ms = timestamp_ms(
        spec.renew_time
            .as_ref()
            .or(spec.acquire_time.as_ref())
            .context("Kubernetes Lease lacks renewTime and acquireTime")?,
    )?;
    let expires_at_ms = expiry_ms(renew_at_ms, duration_seconds)?;
    let transitions = spec.lease_transitions.unwrap_or_default();
    ensure!(transitions >= 0, "Kubernetes Lease transitions are invalid");
    if holder == holder_identity {
        return Ok(AcquisitionDecision::Renew {
            acquired_at_ms: timestamp_ms(
                spec.acquire_time
                    .as_ref()
                    .context("owned Kubernetes Lease lacks acquireTime")?,
            )?,
            transitions,
        });
    }
    if now_ms < expires_at_ms {
        return Ok(AcquisitionDecision::Contended {
            holder: holder.to_string(),
            expires_at_ms,
        });
    }
    Ok(AcquisitionDecision::TakeOver {
        transitions: transitions
            .checked_add(1)
            .context("Kubernetes Lease transition count overflow")?,
    })
}

fn validate_current_lease(
    lease: &Lease,
    proof: &KubernetesLeaseProof,
    scope_sha256: &str,
    now_ms: u64,
) -> Result<()> {
    validate_owned_lease_generation(lease, proof, scope_sha256)?;
    ensure!(
        now_ms < proof.expires_at_ms,
        "storage-recovery Kubernetes Lease expiry has passed"
    );
    Ok(())
}

fn validate_owned_lease_generation(
    lease: &Lease,
    proof: &KubernetesLeaseProof,
    scope_sha256: &str,
) -> Result<()> {
    validate_scope(lease, scope_sha256)?;
    let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
    let acquired_at_ms = timestamp_ms(
        spec.acquire_time
            .as_ref()
            .context("Kubernetes Lease lacks acquireTime")?,
    )?;
    let renew_at_ms = timestamp_ms(
        spec.renew_time
            .as_ref()
            .context("Kubernetes Lease lacks renewTime")?,
    )?;
    let expires_at_ms = expiry_ms(
        renew_at_ms,
        spec.lease_duration_seconds
            .context("Kubernetes Lease lacks leaseDurationSeconds")?,
    )?;
    ensure!(
        lease.uid().as_deref() == Some(proof.uid.as_str())
            && lease.resource_version().as_deref() == Some(proof.resource_version.as_str())
            && spec.holder_identity.as_deref() == Some(proof.holder_identity.as_str())
            && acquired_at_ms == proof.acquired_at_ms
            && renew_at_ms == proof.renew_at_ms
            && expires_at_ms == proof.expires_at_ms,
        "storage-recovery Kubernetes Lease ownership or generation drifted"
    );
    Ok(())
}

fn validate_scope(lease: &Lease, expected_scope_sha256: &str) -> Result<()> {
    ensure!(
        lease
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SCOPE_ANNOTATION))
            .is_some_and(|scope| scope == expected_scope_sha256),
        "Kubernetes Lease scope annotation does not match the storage target"
    );
    Ok(())
}

fn micro_time(timestamp_ms: u64) -> Result<MicroTime> {
    let timestamp_ms = i64::try_from(timestamp_ms)?;
    Ok(MicroTime(
        Utc.timestamp_millis_opt(timestamp_ms)
            .single()
            .context("storage-recovery Lease timestamp is invalid")?,
    ))
}

fn timestamp_ms(timestamp: &MicroTime) -> Result<u64> {
    u64::try_from(timestamp.0.timestamp_millis())
        .context("storage-recovery Lease timestamp precedes the Unix epoch")
}

fn expiry_ms(renew_at_ms: u64, duration_seconds: i32) -> Result<u64> {
    let duration_ms = u64::try_from(duration_seconds)?
        .checked_mul(1_000)
        .context("storage-recovery Lease duration overflow")?;
    renew_at_ms
        .checked_add(duration_ms)
        .context("storage-recovery Lease expiry overflow")
}

fn now_ms() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("system timestamp exceeds u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use axum::{Json, Router, extract::State, http::StatusCode, routing::get};

    use super::*;

    const SCOPE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn lease(holder: &str, renew_at_ms: u64, duration_seconds: i32) -> Lease {
        Lease {
            metadata: ObjectMeta {
                uid: Some("lease-uid".to_string()),
                resource_version: Some("20".to_string()),
                annotations: Some(BTreeMap::from([(
                    SCOPE_ANNOTATION.to_string(),
                    SCOPE.to_string(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(LeaseSpec {
                acquire_time: Some(micro_time(renew_at_ms - 1_000).expect("acquire time")),
                holder_identity: Some(holder.to_string()),
                lease_duration_seconds: Some(duration_seconds),
                lease_transitions: Some(2),
                renew_time: Some(micro_time(renew_at_ms).expect("renew time")),
            }),
        }
    }

    #[derive(Clone)]
    struct LeaseApiState {
        lease: Arc<Mutex<Lease>>,
        renewals: Arc<AtomicUsize>,
        expire_first_committed_renewal: Arc<AtomicBool>,
    }

    async fn get_test_lease(State(state): State<LeaseApiState>) -> Json<Lease> {
        Json(state.lease.lock().expect("Lease state").clone())
    }

    async fn replace_test_lease(
        State(state): State<LeaseApiState>,
        Json(mut lease): Json<Lease>,
    ) -> std::result::Result<Json<Lease>, StatusCode> {
        let current_version = state
            .lease
            .lock()
            .expect("Lease state")
            .metadata
            .resource_version
            .clone()
            .expect("resourceVersion");
        assert_eq!(
            lease.metadata.resource_version.as_deref(),
            Some(current_version.as_str())
        );
        let next_version = current_version.parse::<u64>().expect("numeric version") + 1;
        lease.metadata.uid = Some("lease-uid".to_string());
        lease.metadata.resource_version = Some(next_version.to_string());
        let expire_response = state
            .expire_first_committed_renewal
            .swap(false, Ordering::SeqCst);
        if expire_response {
            lease.spec.as_mut().expect("Lease spec").renew_time =
                Some(micro_time(now_ms().expect("current time") - 10_000).expect("renew time"));
        }
        *state.lease.lock().expect("Lease state") = lease.clone();
        state.renewals.fetch_add(1, Ordering::SeqCst);
        if expire_response {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            Ok(Json(lease))
        }
    }

    #[test]
    fn active_foreign_lease_is_contended() {
        assert_eq!(
            acquisition_decision(&lease("other", 10_000, 30), SCOPE, "run/attempt", 39_999)
                .expect("decision"),
            AcquisitionDecision::Contended {
                holder: "other".to_string(),
                expires_at_ms: 40_000,
            }
        );
    }

    #[test]
    fn expired_foreign_lease_can_be_taken_over_with_transition() {
        assert_eq!(
            acquisition_decision(&lease("other", 10_000, 30), SCOPE, "run/attempt", 40_000)
                .expect("decision"),
            AcquisitionDecision::TakeOver { transitions: 3 }
        );
    }

    #[test]
    fn scope_mismatch_fails_closed() {
        let error = acquisition_decision(
            &lease("other", 10_000, 30),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "run/attempt",
            40_000,
        )
        .expect_err("scope mismatch");
        assert!(error.to_string().contains("scope annotation"));
    }

    #[test]
    fn lost_or_renewed_lease_rejects_next_operation() {
        let proof = KubernetesLeaseProof {
            name: storage_lease_name(SCOPE).expect("name"),
            uid: "lease-uid".to_string(),
            resource_version: "20".to_string(),
            holder_identity: "run/attempt".to_string(),
            scope_sha256: SCOPE.to_string(),
            acquired_at_ms: 9_000,
            renew_at_ms: 10_000,
            expires_at_ms: 40_000,
        };
        validate_current_lease(&lease("run/attempt", 10_000, 30), &proof, SCOPE, 39_999)
            .expect("current lease");

        let mut stolen = lease("other", 11_000, 30);
        stolen.metadata.resource_version = Some("21".to_string());
        let error = validate_current_lease(&stolen, &proof, SCOPE, 11_001)
            .expect_err("lost Lease must fail closed");
        assert!(error.to_string().contains("ownership"), "{error:#}");

        let error =
            validate_current_lease(&lease("run/attempt", 10_000, 30), &proof, SCOPE, 40_000)
                .expect_err("expired Lease must fail closed");
        assert!(error.to_string().contains("expiry"), "{error:#}");

        validate_owned_lease_generation(&lease("run/attempt", 10_000, 30), &proof, SCOPE)
            .expect("expired exact generation remains safe to delete with preconditions");
        assert!(validate_owned_lease_generation(&stolen, &proof, SCOPE).is_err());
    }

    #[test]
    fn lost_renew_response_adopts_only_the_advanced_owned_generation() {
        let previous = KubernetesLeaseProof {
            name: storage_lease_name(SCOPE).expect("name"),
            uid: "lease-uid".to_string(),
            resource_version: "20".to_string(),
            holder_identity: "run/attempt".to_string(),
            scope_sha256: SCOPE.to_string(),
            acquired_at_ms: 9_000,
            renew_at_ms: 10_000,
            expires_at_ms: 40_000,
        };
        let mut advanced = previous.clone();
        advanced.resource_version = "21".to_string();
        advanced.renew_at_ms = 40_001;
        advanced.expires_at_ms = 70_001;
        validate_advanced_owned_renewal(&previous, &advanced, 40_100, false)
            .expect("committed renewal response may be recovered");

        validate_advanced_owned_renewal(&previous, &advanced, 70_001, true)
            .expect("cleanup may recover an expired committed renewal");
        assert!(validate_advanced_owned_renewal(&previous, &advanced, 70_001, false).is_err());

        let mut foreign = advanced.clone();
        foreign.holder_identity = "other/attempt".to_string();
        assert!(validate_advanced_owned_renewal(&previous, &foreign, 40_100, true).is_err());
        let mut replacement = advanced;
        replacement.acquired_at_ms += 1;
        assert!(validate_advanced_owned_renewal(&previous, &replacement, 40_100, true).is_err());
    }

    #[tokio::test]
    async fn cleanup_renews_an_expired_advanced_owned_generation() {
        let observed_at_ms = now_ms().expect("current time");
        let acquired_at_ms = observed_at_ms - 30_000;
        let previous_renew_at_ms = observed_at_ms - 20_000;
        let advanced_renew_at_ms = observed_at_ms - 10_000;
        let name = storage_lease_name(SCOPE).expect("Lease name");
        let mut advanced = lease("run/attempt", advanced_renew_at_ms, 5);
        advanced.metadata.resource_version = Some("21".to_string());
        advanced.spec.as_mut().expect("Lease spec").acquire_time =
            Some(micro_time(acquired_at_ms).expect("acquire time"));
        let state = LeaseApiState {
            lease: Arc::new(Mutex::new(advanced)),
            renewals: Arc::new(AtomicUsize::new(0)),
            expire_first_committed_renewal: Arc::new(AtomicBool::new(false)),
        };
        let app = Router::new()
            .route(
                &format!("/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{name}"),
                get(get_test_lease).put(replace_test_lease),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Lease API server");
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_from(kube::Config::new(
            endpoint.parse().expect("Kubernetes API URI"),
        ))
        .expect("Kubernetes client");
        let adapter = KubernetesStorageLeaseAdapter::new(
            client,
            "test-ns",
            SCOPE,
            "run",
            "attempt",
            Duration::from_secs(5),
        )
        .expect("Lease adapter");
        let previous = KubernetesLeaseProof {
            name,
            uid: "lease-uid".to_string(),
            resource_version: "20".to_string(),
            holder_identity: "run/attempt".to_string(),
            scope_sha256: SCOPE.to_string(),
            acquired_at_ms,
            renew_at_ms: previous_renew_at_ms,
            expires_at_ms: previous_renew_at_ms + 5_000,
        };

        let renewed = adapter
            .renew_for_cleanup(&previous)
            .await
            .expect("cleanup renewal");
        assert_eq!(renewed.resource_version, "22");
        assert!(renewed.expires_at_ms > now_ms().expect("current time"));
        assert_eq!(state.renewals.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn cleanup_retries_when_reconciled_renewal_has_already_expired() {
        let observed_at_ms = now_ms().expect("current time");
        let acquired_at_ms = observed_at_ms - 40_000;
        let previous_renew_at_ms = observed_at_ms - 30_000;
        let advanced_renew_at_ms = observed_at_ms - 20_000;
        let name = storage_lease_name(SCOPE).expect("Lease name");
        let mut advanced = lease("run/attempt", advanced_renew_at_ms, 5);
        advanced.metadata.resource_version = Some("21".to_string());
        advanced.spec.as_mut().expect("Lease spec").acquire_time =
            Some(micro_time(acquired_at_ms).expect("acquire time"));
        let state = LeaseApiState {
            lease: Arc::new(Mutex::new(advanced)),
            renewals: Arc::new(AtomicUsize::new(0)),
            expire_first_committed_renewal: Arc::new(AtomicBool::new(true)),
        };
        let app = Router::new()
            .route(
                &format!("/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{name}"),
                get(get_test_lease).put(replace_test_lease),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Lease API server");
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_from(kube::Config::new(
            endpoint.parse().expect("Kubernetes API URI"),
        ))
        .expect("Kubernetes client");
        let adapter = KubernetesStorageLeaseAdapter::new(
            client,
            "test-ns",
            SCOPE,
            "run",
            "attempt",
            Duration::from_secs(5),
        )
        .expect("Lease adapter");
        let previous = KubernetesLeaseProof {
            name,
            uid: "lease-uid".to_string(),
            resource_version: "20".to_string(),
            holder_identity: "run/attempt".to_string(),
            scope_sha256: SCOPE.to_string(),
            acquired_at_ms,
            renew_at_ms: previous_renew_at_ms,
            expires_at_ms: previous_renew_at_ms + 5_000,
        };

        let renewed = adapter
            .renew_for_cleanup(&previous)
            .await
            .expect("cleanup renewal");
        assert_eq!(renewed.resource_version, "23");
        assert!(renewed.expires_at_ms > now_ms().expect("current time"));
        assert_eq!(state.renewals.load(Ordering::SeqCst), 2);
        server.abort();
    }
}
