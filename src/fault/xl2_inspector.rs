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

//! Minimal, read-only XL2 metadata inspection for storage fault targeting.
//!
//! This is intentionally not a general RustFS metadata implementation. It
//! accepts one explicitly declared on-disk capability profile and extracts only
//! the fields needed to locate the `part.N` shards of an exact object version.
//! Unknown profiles and ambiguous metadata fail closed before any host adapter
//! is allowed to mutate a shard.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xxhash_rust::xxh64::xxh64;

const XL2_MAGIC: &[u8; 4] = b"XL2 ";
const MAX_XL_META_BYTES: usize = 16 * 1024 * 1024;
const MAX_VERSIONS: usize = 10_000;
const MAX_PARTS: usize = 10_000;
const MAX_MSGPACK_DEPTH: usize = 32;

pub const OFFLINE_XL2_INSPECTOR_REVISION: &str = "xl2-1.3-header3-meta3";

const LATEST_RUSTFS_FORMAT_META_VERSION: &str = "1";
const LATEST_RUSTFS_ERASURE_FORMAT_VERSION: &str = "3";
const LATEST_RUSTFS_DISTRIBUTION_ALGORITHM: &str = "SIPMOD+PARITY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Xl2FormatProfile {
    pub file_major: u16,
    pub file_minor: u16,
    pub header_version: u8,
    pub metadata_version: u8,
}

impl Xl2FormatProfile {
    /// XL2 envelope written by the current RustFS `main` filemeta encoder.
    pub const LATEST_RUSTFS: Self = Self {
        file_major: 1,
        file_minor: 3,
        header_version: 3,
        metadata_version: 3,
    };

    /// Compatibility alias for artifacts produced before the profile was
    /// explicitly named after the RustFS writer it follows.
    pub const SUPPORTED: Self = Self::LATEST_RUSTFS;

    pub fn revision(self) -> Result<&'static str> {
        ensure!(
            self == Self::LATEST_RUSTFS,
            "unsupported XL2 capability profile {}.{} header {} metadata {}",
            self.file_major,
            self.file_minor,
            self.header_version,
            self.metadata_version
        );
        Ok(OFFLINE_XL2_INSPECTOR_REVISION)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Xl2ObjectVersionLayout {
    pub inspector_revision: String,
    pub profile: Xl2FormatProfile,
    pub version_id: String,
    pub data_directory: String,
    pub erasure_data_shards: u32,
    pub erasure_parity_shards: u32,
    pub erasure_index: u32,
    pub part_numbers: Vec<u32>,
    pub part_sizes: Vec<u64>,
    pub relative_part_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Xl2InventoryVersionKind {
    ShardParts,
    Inline,
    DeleteMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Xl2InventoryVersionLayout {
    pub version_id: String,
    pub kind: Xl2InventoryVersionKind,
    pub shard_layout: Option<Xl2ObjectVersionLayout>,
}

/// Validates the drive identity that must be read from the same opened volume
/// root as `xl.meta`. This binds an offline mapping to the deployment and exact
/// drive generation instead of trusting a path supplied by the controller.
pub fn validate_format_json_drive(
    bytes: &[u8],
    expected_deployment_id: &str,
    expected_drive_uuid: &str,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "format.json is empty or oversized"
    );
    let expected_deployment = Uuid::parse_str(expected_deployment_id)
        .context("expected RustFS deployment id is not a UUID")?;
    let expected_drive =
        Uuid::parse_str(expected_drive_uuid).context("expected RustFS drive id is not a UUID")?;
    ensure!(
        !expected_deployment.is_nil() && !expected_drive.is_nil(),
        "expected RustFS deployment or drive id is nil"
    );
    let format = serde_json::from_slice::<LatestRustfsFormat>(bytes)
        .context("decode latest RustFS format.json")?;
    let deployment =
        Uuid::parse_str(&format.id).context("RustFS format.json deployment id is not a UUID")?;
    let drive = Uuid::parse_str(&format.erasure.this)
        .context("RustFS format.json drive id is not a UUID")?;
    ensure!(
        format.version == LATEST_RUSTFS_FORMAT_META_VERSION
            && matches!(format.backend.as_str(), "xl" | "xl-single")
            && deployment == expected_deployment
            && format.erasure.version == LATEST_RUSTFS_ERASURE_FORMAT_VERSION
            && drive == expected_drive
            && format.erasure.distribution_algo == LATEST_RUSTFS_DISTRIBUTION_ALGORITHM,
        "format.json does not match the latest RustFS format profile or expected deployment/drive identity"
    );
    ensure!(
        !format.erasure.sets.is_empty() && format.erasure.sets.iter().all(|set| !set.is_empty()),
        "format.json has no complete XL sets"
    );
    let set_width = format.erasure.sets[0].len();
    ensure!(
        format.erasure.sets.iter().all(|set| set.len() == set_width),
        "format.json XL sets do not have a uniform width"
    );
    let mut seen = BTreeSet::new();
    let drives = format
        .erasure
        .sets
        .iter()
        .flatten()
        .map(|id| {
            let id = Uuid::parse_str(id).context("format.json XL set entry is not a UUID")?;
            ensure!(!id.is_nil(), "format.json XL set contains a nil drive UUID");
            ensure!(
                seen.insert(id),
                "format.json XL sets contain a duplicate drive UUID"
            );
            Ok(id)
        })
        .collect::<Result<Vec<_>>>()?;
    let occurrences = drives.iter().filter(|id| **id == expected_drive).count();
    ensure!(
        occurrences == 1,
        "format.json must contain the expected drive exactly once"
    );
    ensure!(
        (format.backend == "xl-single") == format.erasure.sets.iter().all(|set| set.len() == 1),
        "format.json backend does not match the latest RustFS set width"
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
struct LatestRustfsFormat {
    version: String,
    #[serde(rename = "format")]
    backend: String,
    id: String,
    #[serde(rename = "xl")]
    erasure: LatestRustfsErasureFormat,
}

#[derive(Debug, Deserialize)]
struct LatestRustfsErasureFormat {
    version: String,
    this: String,
    sets: Vec<Vec<String>>,
    #[serde(rename = "distributionAlgo")]
    distribution_algo: String,
}

/// Inspects a captured `xl.meta` and returns exactly one non-delete, non-inline
/// version. The caller remains responsible for opening the returned relative
/// paths through `openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV)` and rechecking
/// inode/device/size on the returned file descriptor.
pub fn inspect_xl_meta(bytes: &[u8], requested_version_id: &str) -> Result<Xl2ObjectVersionLayout> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_XL_META_BYTES,
        "xl.meta size must be between 1 and {MAX_XL_META_BYTES} bytes"
    );
    let requested = Uuid::parse_str(requested_version_id)
        .context("offline XL2 inspection requires an explicit UUID version id")?;
    ensure!(
        !requested.is_nil(),
        "offline XL2 inspection does not target null versions"
    );

    let layouts = inspect_all_xl_meta(bytes)?;
    let mut matched = layouts
        .into_iter()
        .filter(|layout| layout.version_id == requested.to_string());
    let layout = matched
        .next()
        .context("requested object version is absent from xl.meta")?;
    ensure!(
        matched.next().is_none(),
        "requested XL2 version is duplicated"
    );
    layout
        .shard_layout
        .context("requested object version is inline and has no shard part path")
}

/// Enumerates every object version from one supported `xl.meta`. Non-inline
/// versions include their declared shard parts; inline versions and delete
/// markers retain their identity without inventing an external part path.
pub fn inspect_all_xl_meta(bytes: &[u8]) -> Result<Vec<Xl2InventoryVersionLayout>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_XL_META_BYTES,
        "xl.meta size must be between 1 and {MAX_XL_META_BYTES} bytes"
    );
    let (profile, metadata) = decode_envelope(bytes)?;
    let revision = profile.revision()?;
    let mut cursor = MsgpackCursor::new(metadata);
    let header_version = cursor.read_u64("XL2 header version")?;
    let metadata_version = cursor.read_u64("XL2 metadata version")?;
    let version_count = cursor.read_u64("XL2 version count")?;
    ensure!(
        header_version == u64::from(profile.header_version)
            && metadata_version == u64::from(profile.metadata_version),
        "XL2 envelope and metadata capability profile disagree"
    );
    let version_count = usize::try_from(version_count).context("XL2 version count overflow")?;
    ensure!(
        version_count <= MAX_VERSIONS,
        "XL2 version count exceeds inspection limit"
    );

    let mut layouts = Vec::with_capacity(version_count);
    let mut version_ids = BTreeSet::new();
    for _ in 0..version_count {
        let header = cursor.read_bin("XL2 version header")?;
        let body = cursor.read_bin("XL2 version metadata")?;
        let parsed_header = parse_version_header(header)?;
        ensure!(
            version_ids.insert(parsed_header.version_id),
            "XL2 metadata contains a duplicate version id"
        );
        if parsed_header.version_type == 2 {
            ensure!(
                parsed_header.flags & 0b110 == 0 && parse_version_type(body)? == 2,
                "XL2 delete-marker header, flags, and body disagree"
            );
            layouts.push(Xl2InventoryVersionLayout {
                version_id: parsed_header.version_id.to_string(),
                kind: Xl2InventoryVersionKind::DeleteMarker,
                shard_layout: None,
            });
            continue;
        }
        ensure!(
            parsed_header.version_type == 1,
            "XL2 metadata contains an unsupported version type"
        );
        let object = parse_version_body(body)?;
        ensure!(
            object.version_type == 1 && object.version_id == parsed_header.version_id,
            "XL2 version header and object body disagree"
        );
        ensure!(
            parsed_header.erasure_data_shards == u64::from(object.erasure_data_shards)
                && parsed_header.erasure_parity_shards == u64::from(object.erasure_parity_shards),
            "XL2 version header and object erasure geometry disagree"
        );
        let header_uses_data_directory = parsed_header.flags & 0b10 != 0;
        let inline = parsed_header.flags & 0b100 != 0;
        ensure!(
            !(header_uses_data_directory && inline),
            "XL2 object version cannot be both inline and data-directory flagged"
        );
        let (kind, shard_layout) = if inline {
            (Xl2InventoryVersionKind::Inline, None)
        } else {
            (
                Xl2InventoryVersionKind::ShardParts,
                Some(object_layout(
                    profile,
                    revision,
                    parsed_header.version_id,
                    object,
                )?),
            )
        };
        layouts.push(Xl2InventoryVersionLayout {
            version_id: parsed_header.version_id.to_string(),
            kind,
            shard_layout,
        });
    }
    ensure!(
        cursor.is_finished(),
        "XL2 metadata has trailing version bytes"
    );

    Ok(layouts)
}

fn parse_version_type(bytes: &[u8]) -> Result<u64> {
    let mut cursor = MsgpackCursor::new(bytes);
    let fields = cursor.read_map_len("version metadata")?;
    let mut version_type = None;
    for _ in 0..fields {
        let key = cursor.read_str("version metadata field")?;
        if key == "Type" {
            set_once(
                &mut version_type,
                cursor.read_u64("version metadata type")?,
                "Type",
            )?;
        } else {
            cursor.skip_value(0)?;
        }
    }
    ensure!(
        cursor.is_finished(),
        "XL2 version metadata has trailing bytes"
    );
    version_type.context("XL2 version metadata lacks Type")
}

fn object_layout(
    profile: Xl2FormatProfile,
    revision: &str,
    version_id: Uuid,
    object: ObjectLayout,
) -> Result<Xl2ObjectVersionLayout> {
    let data_directory = object
        .data_directory
        .context("requested object version has no data directory")?;
    ensure!(
        object.erasure_data_shards > 0
            && object.erasure_parity_shards > 0
            && object.erasure_data_shards >= object.erasure_parity_shards,
        "requested object version has invalid erasure geometry"
    );
    let total_shards = object
        .erasure_data_shards
        .checked_add(object.erasure_parity_shards)
        .context("requested object version erasure geometry overflow")?;
    ensure!(
        object.erasure_index > 0 && object.erasure_index <= total_shards,
        "requested object version has an invalid erasure index"
    );
    ensure!(
        !object.part_numbers.is_empty() && object.part_numbers.len() <= MAX_PARTS,
        "requested object version has no bounded part list"
    );
    ensure!(
        object.part_numbers.len() == object.part_sizes.len()
            && object.part_sizes.iter().all(|size| *size > 0),
        "requested object version has an invalid part-size vector"
    );
    let mut unique_parts = BTreeSet::new();
    ensure!(
        object
            .part_numbers
            .iter()
            .all(|part| *part > 0 && unique_parts.insert(*part)),
        "requested object version has zero or duplicate part numbers"
    );
    let data_directory = data_directory.to_string();
    let relative_part_paths = object
        .part_numbers
        .iter()
        .map(|part| format!("{data_directory}/part.{part}"))
        .collect();

    Ok(Xl2ObjectVersionLayout {
        inspector_revision: revision.to_string(),
        profile,
        version_id: version_id.to_string(),
        data_directory,
        erasure_data_shards: object.erasure_data_shards,
        erasure_parity_shards: object.erasure_parity_shards,
        erasure_index: object.erasure_index,
        part_numbers: object.part_numbers,
        part_sizes: object.part_sizes,
        relative_part_paths,
    })
}

fn decode_envelope(bytes: &[u8]) -> Result<(Xl2FormatProfile, &[u8])> {
    ensure!(bytes.len() >= 18, "xl.meta is truncated");
    ensure!(&bytes[..4] == XL2_MAGIC, "xl.meta has invalid XL2 magic");
    let file_major = u16::from_le_bytes([bytes[4], bytes[5]]);
    let file_minor = u16::from_le_bytes([bytes[6], bytes[7]]);
    ensure!(bytes[8] == 0xc6, "xl.meta metadata must use a bin32 frame");
    let metadata_len = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]) as usize;
    ensure!(
        metadata_len <= MAX_XL_META_BYTES && 13 + metadata_len + 5 <= bytes.len(),
        "xl.meta metadata frame is truncated or oversized"
    );
    let metadata = &bytes[13..13 + metadata_len];
    let crc_offset = 13 + metadata_len;
    ensure!(
        bytes[crc_offset] == 0xce,
        "xl.meta checksum must use a uint32 frame"
    );
    let stored_crc = u32::from_be_bytes([
        bytes[crc_offset + 1],
        bytes[crc_offset + 2],
        bytes[crc_offset + 3],
        bytes[crc_offset + 4],
    ]);
    ensure!(
        stored_crc == xxh64(metadata, 0) as u32,
        "xl.meta metadata checksum mismatch"
    );

    let mut header_cursor = MsgpackCursor::new(metadata);
    let header_version = u8::try_from(header_cursor.read_u64("XL2 header version")?)
        .context("XL2 header version overflow")?;
    let metadata_version = u8::try_from(header_cursor.read_u64("XL2 metadata version")?)
        .context("XL2 metadata version overflow")?;
    Ok((
        Xl2FormatProfile {
            file_major,
            file_minor,
            header_version,
            metadata_version,
        },
        metadata,
    ))
}

#[derive(Debug)]
struct VersionHeader {
    version_id: Uuid,
    version_type: u64,
    flags: u64,
    erasure_parity_shards: u64,
    erasure_data_shards: u64,
}

fn parse_version_header(bytes: &[u8]) -> Result<VersionHeader> {
    let mut cursor = MsgpackCursor::new(bytes);
    ensure!(
        cursor.read_array_len("version header")? == 7,
        "XL2 version header must have seven fields"
    );
    let version_id = uuid_from_bin(cursor.read_bin("version header id")?, "version header id")?;
    cursor.skip_value(0)?; // modification time
    let signature = cursor.read_bin("version header signature")?;
    ensure!(
        signature.len() == 4,
        "XL2 version header signature must be four bytes"
    );
    let version_type = cursor.read_u64("version header type")?;
    let flags = cursor.read_u64("version header flags")?;
    let erasure_parity_shards = cursor.read_u64("version header EC parity")?;
    let erasure_data_shards = cursor.read_u64("version header EC data")?;
    ensure!(
        cursor.is_finished(),
        "XL2 version header has trailing bytes"
    );
    Ok(VersionHeader {
        version_id,
        version_type,
        flags,
        erasure_parity_shards,
        erasure_data_shards,
    })
}

#[derive(Debug)]
struct ObjectLayout {
    version_type: u64,
    version_id: Uuid,
    data_directory: Option<Uuid>,
    erasure_data_shards: u32,
    erasure_parity_shards: u32,
    erasure_index: u32,
    part_numbers: Vec<u32>,
    part_sizes: Vec<u64>,
}

fn parse_version_body(bytes: &[u8]) -> Result<ObjectLayout> {
    let mut cursor = MsgpackCursor::new(bytes);
    let fields = cursor.read_map_len("version metadata")?;
    let mut version_type = None;
    let mut object = None;
    for _ in 0..fields {
        let key = cursor.read_str("version metadata field")?;
        match key {
            "Type" => set_once(
                &mut version_type,
                cursor.read_u64("version metadata type")?,
                "Type",
            )?,
            "V2Obj" => set_once(&mut object, parse_object_body(&mut cursor)?, "V2Obj")?,
            _ => cursor.skip_value(0)?,
        }
    }
    ensure!(
        cursor.is_finished(),
        "XL2 version metadata has trailing bytes"
    );
    let version_type = version_type.context("XL2 version metadata lacks Type")?;
    let mut object = object.context("XL2 object version lacks V2Obj")?;
    object.version_type = version_type;
    Ok(object)
}

fn parse_object_body(cursor: &mut MsgpackCursor<'_>) -> Result<ObjectLayout> {
    ensure!(!cursor.read_nil()?, "XL2 object body is nil");
    let fields = cursor.read_map_len("V2 object")?;
    let mut version_id = None;
    let mut data_directory = None;
    let mut erasure_data_shards = None;
    let mut erasure_parity_shards = None;
    let mut erasure_index = None;
    let mut erasure_algorithm = None;
    let mut checksum_algorithm = None;
    let mut part_numbers = None;
    let mut part_sizes = None;
    for _ in 0..fields {
        let key = cursor.read_str("V2 object field")?;
        match key {
            "ID" => set_once(
                &mut version_id,
                uuid_from_bin(cursor.read_bin("V2 object ID")?, "V2 object ID")?,
                "ID",
            )?,
            "DDir" => {
                let id = uuid_from_bin(cursor.read_bin("V2 object data directory")?, "DDir")?;
                set_once(
                    &mut data_directory,
                    if id.is_nil() { None } else { Some(id) },
                    "DDir",
                )?;
            }
            "EcAlgo" => set_once(
                &mut erasure_algorithm,
                cursor.read_u64("V2 object erasure algorithm")?,
                "EcAlgo",
            )?,
            "EcM" => set_once(
                &mut erasure_data_shards,
                read_u32(cursor, "V2 object EC data shards")?,
                "EcM",
            )?,
            "EcN" => set_once(
                &mut erasure_parity_shards,
                read_u32(cursor, "V2 object EC parity shards")?,
                "EcN",
            )?,
            "EcIndex" => set_once(
                &mut erasure_index,
                read_u32(cursor, "V2 object EC index")?,
                "EcIndex",
            )?,
            "CSumAlgo" => set_once(
                &mut checksum_algorithm,
                cursor.read_u64("V2 object checksum algorithm")?,
                "CSumAlgo",
            )?,
            "PartNums" => {
                let len = cursor.read_array_len("V2 object part numbers")?;
                ensure!(
                    len <= MAX_PARTS,
                    "V2 object part list exceeds inspection limit"
                );
                let mut parts = Vec::with_capacity(len);
                for _ in 0..len {
                    parts.push(read_u32(cursor, "V2 object part number")?);
                }
                set_once(&mut part_numbers, parts, "PartNums")?;
            }
            "PartSizes" => {
                let len = cursor.read_array_len("V2 object part sizes")?;
                ensure!(
                    len <= MAX_PARTS,
                    "V2 object part-size list exceeds inspection limit"
                );
                let mut sizes = Vec::with_capacity(len);
                for _ in 0..len {
                    sizes.push(cursor.read_u64("V2 object part size")?);
                }
                set_once(&mut part_sizes, sizes, "PartSizes")?;
            }
            _ => cursor.skip_value(0)?,
        }
    }
    ensure!(
        erasure_algorithm == Some(1),
        "V2 object uses an unsupported erasure algorithm"
    );
    ensure!(
        checksum_algorithm == Some(1),
        "V2 object uses an unsupported bitrot checksum algorithm"
    );
    Ok(ObjectLayout {
        version_type: 0,
        version_id: version_id.context("V2 object lacks ID")?,
        data_directory: data_directory.context("V2 object lacks DDir")?,
        erasure_data_shards: erasure_data_shards.context("V2 object lacks EcM")?,
        erasure_parity_shards: erasure_parity_shards.context("V2 object lacks EcN")?,
        erasure_index: erasure_index.context("V2 object lacks EcIndex")?,
        part_numbers: part_numbers.context("V2 object lacks PartNums")?,
        part_sizes: part_sizes.context("V2 object lacks PartSizes")?,
    })
}

fn uuid_from_bin(bytes: &[u8], label: &str) -> Result<Uuid> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .with_context(|| format!("{label} must be 16 bytes"))?;
    Ok(Uuid::from_bytes(bytes))
}

fn read_u32(cursor: &mut MsgpackCursor<'_>, label: &str) -> Result<u32> {
    u32::try_from(cursor.read_u64(label)?).with_context(|| format!("{label} overflow"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, field: &str) -> Result<()> {
    ensure!(slot.is_none(), "XL2 metadata contains duplicate {field}");
    *slot = Some(value);
    Ok(())
}

struct MsgpackCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> MsgpackCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_byte(&mut self, label: &str) -> Result<u8> {
        let byte = self
            .bytes
            .get(self.offset)
            .copied()
            .with_context(|| format!("truncated MessagePack {label}"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize, label: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .with_context(|| format!("MessagePack {label} length overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .with_context(|| format!("truncated MessagePack {label}"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_u64(&mut self, label: &str) -> Result<u64> {
        let marker = self.read_byte(label)?;
        match marker {
            0x00..=0x7f => Ok(u64::from(marker)),
            0xcc => Ok(u64::from(self.read_byte(label)?)),
            0xcd => Ok(u64::from(u16::from_be_bytes(self.take_array(label)?))),
            0xce => Ok(u64::from(u32::from_be_bytes(self.take_array(label)?))),
            0xcf => Ok(u64::from_be_bytes(self.take_array(label)?)),
            _ => bail!("MessagePack {label} is not an unsigned integer"),
        }
    }

    fn read_array_len(&mut self, label: &str) -> Result<usize> {
        let marker = self.read_byte(label)?;
        match marker {
            0x90..=0x9f => Ok(usize::from(marker & 0x0f)),
            0xdc => Ok(usize::from(u16::from_be_bytes(self.take_array(label)?))),
            0xdd => usize::try_from(u32::from_be_bytes(self.take_array(label)?))
                .with_context(|| format!("MessagePack {label} length overflow")),
            _ => bail!("MessagePack {label} is not an array"),
        }
    }

    fn read_map_len(&mut self, label: &str) -> Result<usize> {
        let marker = self.read_byte(label)?;
        match marker {
            0x80..=0x8f => Ok(usize::from(marker & 0x0f)),
            0xde => Ok(usize::from(u16::from_be_bytes(self.take_array(label)?))),
            0xdf => usize::try_from(u32::from_be_bytes(self.take_array(label)?))
                .with_context(|| format!("MessagePack {label} length overflow")),
            _ => bail!("MessagePack {label} is not a map"),
        }
    }

    fn read_bin(&mut self, label: &str) -> Result<&'a [u8]> {
        let marker = self.read_byte(label)?;
        let len = match marker {
            0xc4 => usize::from(self.read_byte(label)?),
            0xc5 => usize::from(u16::from_be_bytes(self.take_array(label)?)),
            0xc6 => usize::try_from(u32::from_be_bytes(self.take_array(label)?))
                .with_context(|| format!("MessagePack {label} length overflow"))?,
            _ => bail!("MessagePack {label} is not binary"),
        };
        self.take(len, label)
    }

    fn read_str(&mut self, label: &str) -> Result<&'a str> {
        let marker = self.read_byte(label)?;
        let len = match marker {
            0xa0..=0xbf => usize::from(marker & 0x1f),
            0xd9 => usize::from(self.read_byte(label)?),
            0xda => usize::from(u16::from_be_bytes(self.take_array(label)?)),
            0xdb => usize::try_from(u32::from_be_bytes(self.take_array(label)?))
                .with_context(|| format!("MessagePack {label} length overflow"))?,
            _ => bail!("MessagePack {label} is not a string"),
        };
        std::str::from_utf8(self.take(len, label)?)
            .with_context(|| format!("MessagePack {label} is not UTF-8"))
    }

    fn read_nil(&mut self) -> Result<bool> {
        if self.bytes.get(self.offset) == Some(&0xc0) {
            self.offset += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn take_array<const N: usize>(&mut self, label: &str) -> Result<[u8; N]> {
        self.take(N, label)?
            .try_into()
            .with_context(|| format!("truncated MessagePack {label}"))
    }

    fn skip_value(&mut self, depth: usize) -> Result<()> {
        ensure!(
            depth < MAX_MSGPACK_DEPTH,
            "MessagePack nesting exceeds inspection limit"
        );
        let marker = self.read_byte("value")?;
        let (children, payload) = match marker {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => (0, 0),
            0x80..=0x8f => (usize::from(marker & 0x0f) * 2, 0),
            0x90..=0x9f => (usize::from(marker & 0x0f), 0),
            0xa0..=0xbf => (0, usize::from(marker & 0x1f)),
            0xc4 | 0xd9 => (0, usize::from(self.read_byte("length")?)),
            0xc5 | 0xda => (
                0,
                usize::from(u16::from_be_bytes(self.take_array("length")?)),
            ),
            0xc6 | 0xdb => (
                0,
                usize::try_from(u32::from_be_bytes(self.take_array("length")?))
                    .context("MessagePack length overflow")?,
            ),
            0xc7 => {
                let len = usize::from(self.read_byte("extension length")?);
                (0, len + 1)
            }
            0xc8 => {
                let len = usize::from(u16::from_be_bytes(self.take_array("extension length")?));
                (0, len + 1)
            }
            0xc9 => {
                let len = usize::try_from(u32::from_be_bytes(self.take_array("extension length")?))
                    .context("MessagePack extension length overflow")?;
                (0, len + 1)
            }
            0xca | 0xce | 0xd2 => (0, 4),
            0xcb | 0xcf | 0xd3 => (0, 8),
            0xcc | 0xd0 => (0, 1),
            0xcd | 0xd1 => (0, 2),
            0xd4 => (0, 2),
            0xd5 => (0, 3),
            0xd6 => (0, 5),
            0xd7 => (0, 9),
            0xd8 => (0, 17),
            0xdc => (
                usize::from(u16::from_be_bytes(self.take_array("array length")?)),
                0,
            ),
            0xdd => (
                usize::try_from(u32::from_be_bytes(self.take_array("array length")?))
                    .context("MessagePack array length overflow")?,
                0,
            ),
            0xde => (
                usize::from(u16::from_be_bytes(self.take_array("map length")?)) * 2,
                0,
            ),
            0xdf => (
                usize::try_from(u32::from_be_bytes(self.take_array("map length")?))
                    .context("MessagePack map length overflow")?
                    .checked_mul(2)
                    .context("MessagePack map length overflow")?,
                0,
            ),
            0xc1 => bail!("MessagePack contains a reserved marker"),
        };
        self.take(payload, "value payload")?;
        ensure!(
            children <= self.bytes.len().saturating_sub(self.offset),
            "MessagePack container length exceeds remaining input"
        );
        for _ in 0..children {
            self.skip_value(depth + 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) use tests::{fixture as test_fixture, inline_fixture as test_inline_fixture};

#[cfg(test)]
mod tests {
    use super::*;
    use rmp::encode::{
        write_array_len, write_bin, write_i64, write_map_len, write_nil, write_sint, write_str,
        write_uint, write_uint8,
    };

    const VERSION: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const DATA_DIR: &str = "fedcba98-7654-3210-fedc-ba9876543210";
    const DEPLOYMENT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const DRIVE: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    pub(crate) fn fixture(version: &str, data_dir: Option<&str>, parts: &[u32]) -> Vec<u8> {
        fixture_with_layout(version, data_dir, parts, &vec![1024; parts.len()], 0b10)
    }

    pub(crate) fn inline_fixture(version: &str) -> Vec<u8> {
        fixture_with_layout(version, None, &[1], &[4096], 0b100)
    }

    fn fixture_with_layout(
        version: &str,
        data_dir: Option<&str>,
        parts: &[u32],
        part_sizes: &[u64],
        flags: u64,
    ) -> Vec<u8> {
        let version = Uuid::parse_str(version).expect("version");
        let data_dir = data_dir.map(|value| Uuid::parse_str(value).expect("data directory"));

        let mut header = Vec::new();
        write_array_len(&mut header, 7).expect("array");
        write_bin(&mut header, version.as_bytes()).expect("version id");
        write_i64(&mut header, 1).expect("modification time");
        write_bin(&mut header, &[1, 2, 3, 4]).expect("signature");
        for value in [1_u64, flags, 4, 4] {
            write_uint8(&mut header, u8::try_from(value).expect("header byte"))
                .expect("header field");
        }

        // Keep this in the same field order and encoding shape as
        // RustFS MetaObject::encode_to, including fields the inspector skips.
        let mut object = Vec::new();
        write_map_len(&mut object, 17).expect("object map");
        write_str(&mut object, "ID").expect("ID key");
        write_bin(&mut object, version.as_bytes()).expect("ID");
        write_str(&mut object, "DDir").expect("DDir key");
        write_bin(&mut object, data_dir.unwrap_or(Uuid::nil()).as_bytes()).expect("DDir");
        for (key, value) in [("EcAlgo", 1_u64), ("EcM", 4), ("EcN", 4)] {
            write_str(&mut object, key).expect("EC key");
            write_uint(&mut object, value).expect("EC value");
        }
        write_str(&mut object, "EcBSize").expect("block size key");
        write_sint(&mut object, 1 << 20).expect("block size");
        write_str(&mut object, "EcIndex").expect("index key");
        write_sint(&mut object, 2).expect("index");
        write_str(&mut object, "EcDist").expect("distribution key");
        write_array_len(&mut object, 8).expect("distribution array");
        for value in 1..=8 {
            write_uint(&mut object, value).expect("distribution value");
        }
        write_str(&mut object, "CSumAlgo").expect("checksum key");
        write_uint(&mut object, 1).expect("checksum algorithm");
        write_str(&mut object, "PartNums").expect("parts key");
        write_array_len(&mut object, parts.len() as u32).expect("parts array");
        for part in parts {
            write_uint(&mut object, u64::from(*part)).expect("part");
        }
        write_str(&mut object, "PartETags").expect("part ETags key");
        write_nil(&mut object).expect("part ETags");
        write_str(&mut object, "PartSizes").expect("part sizes key");
        write_array_len(&mut object, part_sizes.len() as u32).expect("part sizes array");
        for size in part_sizes {
            write_uint(&mut object, *size).expect("part size");
        }
        write_str(&mut object, "PartASizes").expect("part actual sizes key");
        write_nil(&mut object).expect("part actual sizes");
        write_str(&mut object, "Size").expect("object size key");
        write_sint(&mut object, part_sizes.iter().sum::<u64>() as i64).expect("object size");
        write_str(&mut object, "MTime").expect("modification time key");
        write_sint(&mut object, 1).expect("modification time");
        write_str(&mut object, "MetaSys").expect("system metadata key");
        write_nil(&mut object).expect("system metadata");
        write_str(&mut object, "MetaUsr").expect("user metadata key");
        write_nil(&mut object).expect("user metadata");

        let mut body = Vec::new();
        write_map_len(&mut body, 3).expect("body map");
        write_str(&mut body, "Type").expect("type key");
        write_uint(&mut body, 1).expect("type");
        write_str(&mut body, "V2Obj").expect("object key");
        body.extend_from_slice(&object);
        write_str(&mut body, "v").expect("write-version key");
        write_uint(&mut body, 1).expect("write version");

        let mut metadata = Vec::new();
        write_uint(&mut metadata, 3).expect("header version");
        write_uint(&mut metadata, 3).expect("metadata version");
        write_sint(&mut metadata, 1).expect("version count");
        write_bin(&mut metadata, &header).expect("header");
        write_bin(&mut metadata, &body).expect("body");

        let mut xl = Vec::new();
        xl.extend_from_slice(XL2_MAGIC);
        xl.extend_from_slice(&1_u16.to_le_bytes());
        xl.extend_from_slice(&3_u16.to_le_bytes());
        xl.push(0xc6);
        xl.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        xl.extend_from_slice(&metadata);
        xl.push(0xce);
        xl.extend_from_slice(&(xxh64(&metadata, 0) as u32).to_be_bytes());
        xl
    }

    #[test]
    fn inspects_exact_version_and_returns_only_part_paths() {
        let layout = inspect_xl_meta(&fixture(VERSION, Some(DATA_DIR), &[1, 3]), VERSION)
            .expect("inspect XL2 fixture");

        assert_eq!(layout.profile, Xl2FormatProfile::LATEST_RUSTFS);
        assert_eq!(layout.inspector_revision, OFFLINE_XL2_INSPECTOR_REVISION);
        assert_eq!(layout.version_id, VERSION);
        assert_eq!(layout.data_directory, DATA_DIR);
        assert_eq!(layout.erasure_data_shards, 4);
        assert_eq!(layout.erasure_parity_shards, 4);
        assert_eq!(layout.erasure_index, 2);
        assert_eq!(layout.part_sizes, [1024, 1024]);
        assert_eq!(
            layout.relative_part_paths,
            [format!("{DATA_DIR}/part.1"), format!("{DATA_DIR}/part.3")]
        );
    }

    #[test]
    fn inventory_accepts_shard_parts_when_header_data_directory_flag_is_clear() {
        let layout = inspect_xl_meta(
            &fixture_with_layout(VERSION, Some(DATA_DIR), &[1], &[1024], 0),
            VERSION,
        )
        .expect("inspect XL2 shard object without the legacy data-directory flag");

        assert_eq!(layout.version_id, VERSION);
        assert_eq!(layout.data_directory, DATA_DIR);
        assert_eq!(layout.relative_part_paths, [format!("{DATA_DIR}/part.1")]);
    }

    #[test]
    fn inventory_preserves_inline_version_without_inventing_a_part_path() {
        let layouts = inspect_all_xl_meta(&inline_fixture(VERSION)).expect("inspect inline XL2");
        assert_eq!(layouts.len(), 1);
        assert_eq!(layouts[0].version_id, VERSION);
        assert_eq!(layouts[0].kind, Xl2InventoryVersionKind::Inline);
        assert!(layouts[0].shard_layout.is_none());
        assert!(inspect_xl_meta(&inline_fixture(VERSION), VERSION).is_err());
    }

    #[test]
    fn rejects_unknown_profile_before_body_interpretation() {
        let mut xl = fixture(VERSION, Some(DATA_DIR), &[1]);
        xl[6..8].copy_from_slice(&4_u16.to_le_bytes());
        let error = inspect_xl_meta(&xl, VERSION).expect_err("unknown profile");
        assert!(
            error
                .to_string()
                .contains("unsupported XL2 capability profile")
        );
    }

    #[test]
    fn rejects_corrupt_crc_missing_data_directory_and_unsafe_parts() {
        let mut corrupt = fixture(VERSION, Some(DATA_DIR), &[1]);
        let crc = corrupt.len() - 1;
        corrupt[crc] ^= 1;
        assert!(inspect_xl_meta(&corrupt, VERSION).is_err());

        assert!(inspect_xl_meta(&fixture(VERSION, None, &[1]), VERSION).is_err());
        assert!(inspect_xl_meta(&fixture(VERSION, Some(DATA_DIR), &[0]), VERSION).is_err());
        assert!(inspect_xl_meta(&fixture(VERSION, Some(DATA_DIR), &[1, 1]), VERSION).is_err());
        assert!(
            inspect_xl_meta(
                &fixture_with_layout(VERSION, Some(DATA_DIR), &[1], &[], 0b10),
                VERSION
            )
            .is_err()
        );
        assert!(
            inspect_xl_meta(
                &fixture_with_layout(VERSION, Some(DATA_DIR), &[1], &[1024], 0b110),
                VERSION
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_absent_or_null_version_identity() {
        assert!(
            inspect_xl_meta(
                &fixture(VERSION, Some(DATA_DIR), &[1]),
                "11111111-1111-1111-1111-111111111111"
            )
            .is_err()
        );
        assert!(
            inspect_xl_meta(
                &fixture(VERSION, Some(DATA_DIR), &[1]),
                "00000000-0000-0000-0000-000000000000"
            )
            .is_err()
        );
    }

    #[test]
    fn format_json_binds_deployment_and_drive_generation() {
        let format = serde_json::json!({
            "version": "1",
            "format": "xl",
            "id": DEPLOYMENT,
            "xl": {
                "version": "3",
                "this": DRIVE,
                "sets": [[DRIVE, "cccccccc-cccc-cccc-cccc-cccccccccccc"]],
                "distributionAlgo": "SIPMOD+PARITY"
            }
        });
        let bytes = serde_json::to_vec(&format).expect("format.json");
        validate_format_json_drive(&bytes, DEPLOYMENT, DRIVE).expect("drive identity");

        assert!(validate_format_json_drive(&bytes, DEPLOYMENT, VERSION).is_err());
        let mut duplicate = format;
        duplicate["xl"]["sets"] = serde_json::json!([[DRIVE, DRIVE]]);
        assert!(
            validate_format_json_drive(
                &serde_json::to_vec(&duplicate).expect("duplicate format.json"),
                DEPLOYMENT,
                DRIVE
            )
            .is_err()
        );
    }

    #[test]
    fn format_json_requires_the_latest_rustfs_layout_profile() {
        let latest = serde_json::json!({
            "version": "1",
            "format": "xl",
            "id": DEPLOYMENT,
            "xl": {
                "version": "3",
                "this": DRIVE,
                "sets": [[DRIVE, "cccccccc-cccc-cccc-cccc-cccccccccccc"]],
                "distributionAlgo": "SIPMOD+PARITY"
            }
        });
        for pointer in ["/version", "/xl/version", "/xl/distributionAlgo"] {
            let mut stale = latest.clone();
            *stale.pointer_mut(pointer).expect("profile field") = serde_json::json!("legacy");
            assert!(
                validate_format_json_drive(
                    &serde_json::to_vec(&stale).expect("stale format.json"),
                    DEPLOYMENT,
                    DRIVE
                )
                .is_err(),
                "accepted stale profile field {pointer}"
            );
        }

        let mut mismatched_backend = latest;
        mismatched_backend["format"] = serde_json::json!("xl-single");
        assert!(
            validate_format_json_drive(
                &serde_json::to_vec(&mismatched_backend).expect("mismatched format.json"),
                DEPLOYMENT,
                DRIVE
            )
            .is_err()
        );

        let mut uneven_sets = mismatched_backend;
        uneven_sets["format"] = serde_json::json!("xl");
        uneven_sets["xl"]["sets"] = serde_json::json!([
            [DRIVE, "cccccccc-cccc-cccc-cccc-cccccccccccc"],
            ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
        ]);
        assert!(
            validate_format_json_drive(
                &serde_json::to_vec(&uneven_sets).expect("uneven format.json"),
                DEPLOYMENT,
                DRIVE
            )
            .is_err()
        );
    }
}
