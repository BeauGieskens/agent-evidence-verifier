//! Checkpointed Local Log stuff.

use std::time::Duration;

use bytes::Bytes;
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use serde_with::{DurationSeconds, serde_as};
use sha2::{Digest, Sha256};

// SHA-256 digest size in bytes.
const NODE_SIZE: usize = 256 / 8;

/// A SHA-256 MMR node value.
type NodeBytes = [u8; NODE_SIZE];

/// Decodes a concatenated accumulator without allowing partial node values.
fn deserialize_accumulator<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Bytes::deserialize(deserializer)?;
    if !bytes.len().is_multiple_of(NODE_SIZE) {
        return Err(serde::de::Error::custom(format!(
            "accumulator length {} is not a multiple of {NODE_SIZE}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Checkpoint {
    kind: CheckpointKind,
    /// MMR tree size (node count) the checkpoint commits to.
    log_size: usize,
    /// The number of entries, given by `leaf_count(log_size - 1)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_count: Option<usize>,
    /// The accumulator at `log_size`.
    #[serde(deserialize_with = "deserialize_accumulator")]
    commitment: Bytes,
    /// Log size of this log's previous checkpoint; 0 for the first.
    prev_size: usize,
    /// The previous checkpoint's commitment; zero-length for the first.
    #[serde(deserialize_with = "deserialize_accumulator")]
    prev_commitment: Bytes,
    /// The MMR profile consistency proof from `prev_size` to `log_size`.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "cbor_bytes")]
    consistency_proof: Option<ConsistencyProof>,
    /// Issuance time.
    issued_at: Timestamp,
    /// Declared maximum time between checkpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    cadence: Option<Duration>,
}

impl Checkpoint {
    fn validate(&self) -> Result<(), String> {
        if !valid_mmr_node_count(self.log_size) {
            return Err(format!("invalid log_size {}", self.log_size));
        }
        if !valid_mmr_node_count(self.prev_size) {
            return Err(format!("invalid prev_size {}", self.prev_size));
        }
        if self.prev_size > self.log_size {
            return Err(format!(
                "prev_size {} is greater than log_size {}",
                self.prev_size, self.log_size
            ));
        }

        if self.commitment.len() != NODE_SIZE * mmr_peak_count(self.log_size) as usize {
            return Err(format!(
                "commitment length {} does not match log_size {}",
                self.commitment.len(),
                self.log_size
            ));
        }
        if self.prev_commitment.len() != NODE_SIZE * mmr_peak_count(self.prev_size) as usize {
            return Err(format!(
                "prev_commitment length {} does not match prev_size {}",
                self.prev_commitment.len(),
                self.prev_size
            ));
        }

        if let Some(leaf_count) = self.leaf_count
            && leaf_count != mmr_leaf_count(self.log_size)
        {
            return Err(format!(
                "leaf_count {} does not match log_size {}",
                leaf_count, self.log_size
            ));
        }

        if self.prev_size == 0 && self.consistency_proof.is_some() {
            return Err("consistency proof should not be present".into());
        }

        if self.prev_size == self.log_size {
            if self.consistency_proof.is_some() {
                return Err("consistency proof should be empty when prev_size == log_size".into());
            }
            if self.commitment != self.prev_commitment {
                return Err(
                    "commitment should equal prev_commitment when prev_size == log_size".into(),
                );
            }
            return Ok(());
        }

        let Some(consistency_proof) = &self.consistency_proof else {
            return Err("consistency proof is required when prev_size < log_size".into());
        };
        consistency_proof.validate(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CheckpointKind {
    CllCheckpoint,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
struct ConsistencyProof {
    tree_size_1: usize,
    tree_size_2: usize,
    #[serde_as(as = "Vec<Vec<serde_with::Bytes>>")]
    consistency_paths: Vec<Vec<NodeBytes>>,
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    right_peaks: Vec<NodeBytes>,
}

impl ConsistencyProof {
    fn validate(&self, checkpoint: &Checkpoint) -> Result<(), String> {
        if self.tree_size_1 != checkpoint.prev_size {
            return Err(format!(
                "tree-size-1 {} does not match checkpoint prev_size {}",
                self.tree_size_1, checkpoint.prev_size
            ));
        }
        if self.tree_size_2 != checkpoint.log_size {
            return Err(format!(
                "tree-size-2 {} does not match checkpoint log_size {}",
                self.tree_size_2, checkpoint.log_size
            ));
        }

        let (prev_accumulator, remainder) = checkpoint.prev_commitment.as_chunks::<NODE_SIZE>();
        if !remainder.is_empty() {
            return Err("prev_commitment contains a partial node value".into());
        }

        let (roots, right_peak_count) = consistent_roots(
            self.tree_size_1,
            self.tree_size_2,
            prev_accumulator,
            &self.consistency_paths,
        )?;
        if self.right_peaks.len() != right_peak_count {
            return Err(format!(
                "right_peaks count {} does not match expected count {right_peak_count}",
                self.right_peaks.len()
            ));
        }
        let rebuilt = roots.iter().chain(&self.right_peaks).flatten();
        if !rebuilt.eq(checkpoint.commitment.iter()) {
            return Err("rebuilt commitment does not match checkpoint commitment".into());
        }

        Ok(())
    }
}

fn valid_mmr_node_count(count: usize) -> bool {
    let leaves = mmr_leaf_count(count);
    count == 2 * leaves - leaves.count_ones() as usize
}

fn mmr_peak_count(node_count: usize) -> u32 {
    let mut remaining = node_count as u128;
    let mut count = 0;
    while remaining > 0 {
        let bits = u128::BITS - (remaining + 1).leading_zeros();
        let tree_size = (1u128 << (bits - 1)) - 1;

        remaining -= tree_size;
        count += 1;
    }
    count
}

fn mmr_leaf_count(node_count: usize) -> usize {
    let mut remaining = node_count as u128;
    let mut count = 0;
    while remaining > 0 {
        let bits = u128::BITS - (remaining + 1).leading_zeros();
        let tree_size = (1u128 << (bits - 1)) - 1;

        remaining -= tree_size;
        count += (tree_size + 1).div_ceil(2) as usize;
    }
    count
}

fn mmr_peak_idxs(i: usize) -> Vec<usize> {
    let mut peaks = Vec::new();
    let mut remaining = i as u128 + 1;
    let mut peak = 0;
    while remaining > 0 {
        let bits = u128::BITS - (remaining + 1).leading_zeros();
        let tree_size = (1u128 << (bits - 1)) - 1;

        peak += tree_size as usize;
        peaks.push(peak - 1);
        remaining -= tree_size;
    }
    peaks
}

fn mmr_idx_height(i: usize) -> u32 {
    let mut pos = i as u128 + 1;
    while pos & (pos + 1) != 0 {
        pos -= most_sig_bit(pos) - 1
    }
    pos.bit_width() - 1
}

/// Returns the mask for the most significant bit in pos.
fn most_sig_bit(pos: u128) -> u128 {
    1 << (u128::BITS - pos.leading_zeros() - 1)
}

fn hash_pospair64(pos: usize, a: &NodeBytes, b: &NodeBytes) -> NodeBytes {
    let mut hasher = Sha256::new();
    hasher.update((pos as u64).to_be_bytes());
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

fn included_root(mut idx: usize, nodehash: &NodeBytes, proof: &[NodeBytes]) -> NodeBytes {
    let mut root = *nodehash;
    let g = mmr_idx_height(idx);
    for (g, sibling) in (g..).zip(proof.iter()) {
        if mmr_idx_height(idx + 1) > g {
            idx += 1;
            root = hash_pospair64(idx + 1, sibling, &root);
        } else {
            idx += 2 << g;
            root = hash_pospair64(idx + 1, &root, sibling);
        }
    }
    root
}

fn consistent_roots(
    size_from: usize,
    size_to: usize,
    from_accumulator: &[NodeBytes],
    proofs: &[Vec<NodeBytes>],
) -> Result<(Vec<NodeBytes>, usize), String> {
    if size_from >= size_to {
        return Err(format!(
            "consistency proof requires increasing sizes, got {size_from} -> {size_to}"
        ));
    }
    if !valid_mmr_node_count(size_from) || !valid_mmr_node_count(size_to) {
        return Err("consistency proof sizes must be complete MMR sizes".into());
    }
    let from_peaks = if size_from == 0 {
        Vec::new()
    } else {
        mmr_peak_idxs(size_from - 1)
    };
    let to_peaks = mmr_peak_idxs(size_to - 1);
    if from_accumulator.len() != from_peaks.len() {
        return Err("accumulator count does not match origin peak count".into());
    }
    if proofs.len() != from_peaks.len() {
        return Err("consistency path count does not match origin peak count".into());
    }

    let mut roots = Vec::new();
    let mut target_idx = 0;
    for ((peak, nodehash), proof) in from_peaks.into_iter().zip(from_accumulator).zip(proofs) {
        // Append-only growth cannot split an existing perfect tree; the first
        // target peak at or after an origin peak is its ancestor.
        while peak > to_peaks[target_idx] {
            target_idx += 1;
        }
        let target_peak = to_peaks[target_idx];
        let expected = (mmr_idx_height(target_peak) - mmr_idx_height(peak)) as usize;
        if proof.len() != expected {
            return Err(format!(
                "consistency path for peak {peak} has length {}, expected {expected}",
                proof.len()
            ));
        }
        let root = included_root(peak, nodehash, proof);
        if target_idx == roots.len() {
            roots.push(root);
        } else if roots.last() != Some(&root) {
            return Err(format!(
                "consistency paths reconstruct different values for target peak {target_peak}"
            ));
        }
    }
    let right_peak_count = to_peaks.len() - roots.len();
    Ok((roots, right_peak_count))
}

/// Encodes an optional proof as a byte string containing its CBOR array.
mod cbor_bytes {
    use serde::{Deserializer, Serializer, de::Visitor};

    use super::ConsistencyProof;

    pub fn serialize<S: Serializer>(
        proof: &Option<ConsistencyProof>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let proof = proof
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("absent proof must be skipped"))?;
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(proof, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ConsistencyProof>, D::Error> {
        deserializer.deserialize_bytes(ProofVisitor).map(Some)
    }

    struct ProofVisitor;

    impl<'de> Visitor<'de> for ProofVisitor {
        type Value = ConsistencyProof;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a byte string containing a CBOR consistency proof")
        }

        fn visit_bytes<E: serde::de::Error>(self, mut bytes: &[u8]) -> Result<Self::Value, E> {
            let proof = ciborium::de::from_reader(&mut bytes).map_err(E::custom)?;
            if !bytes.is_empty() {
                return Err(E::custom("trailing bytes after CBOR consistency proof"));
            }
            Ok(proof)
        }

        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&bytes)
        }
    }
}
