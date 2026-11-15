use bytes::Bytes;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{Digest, EvidenceSubject};

struct ArtifactResponse {
    /// The actual artifact.
    artifact: Artifact,
    /// The resolved coverage anchor.
    ///
    /// - If [`EvidenceCoverage::ExpectedPin`] was requested, this is verified to match the request.
    /// - If [`EvidenceCoverage::MinFreshness`] was requested, this is the anchor the responder
    ///   selected to satisfy the request.
    anchor: Digest,
    verification_material: (),
    request_digest: Digest,
    issuance_time: Timestamp,
    signature: (),
}

enum Artifact {
    Bytes(Bytes),
    DerivationResult(Digest),
}

struct SignedRefusal {
    /// The digest of the request being refused, computed over the request bytes as received.
    request_digest: Digest,
    reason: RefusalReason,
    issuance_time: Timestamp,
    signature: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum RefusalReason {
    /// The subject does not resolve to evidence the responder holds.
    NoSuchSubject,
    /// The responder cannot satisfy the coverage constraint as stated.
    CoverageUnsatisfiable,
    /// The responder does not support the named derivation.
    DerivationUnsupported,
    /// The responder declines without further characterization.
    PolicyDeclined,
    /// The responder cannot answer within the stated deadline.
    DeadlineUnmet,
    /// The request is not well-formed as specified by the defining document.
    RequestMalformed,
    /// The responder's retention commitment for this subject has lapsed.
    RetentionExpired,
    /// The responder declines for a limit of its own (load, size, a transient fault), whoever asks.
    CapacityExceeded,
    /// The requester authentication a deployment profile defines does not verify.
    RequestUnauthenticated,
}

/// A signed statement that a named subject will remain answerable under this interaction until a
/// stated time.
struct RetentionCommitment {
    subject: EvidenceSubject,
    // TODO: what is the right type?
    evidence_stream: Option<()>,
    /// The time after which the commitment lapses.
    until: Timestamp,
}
