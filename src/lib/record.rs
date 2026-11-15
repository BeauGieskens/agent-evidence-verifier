use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{CorrelationIdentifier, Digest, Position, serde::digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Record {
    seq: Position,
    #[serde(with = "digest")]
    record_id: Digest,
    record_type: String,
    epistemic_type: EpistemicType,
    committed_at: Option<Timestamp>,
    event_time_claim: Option<Timestamp>,
    #[serde(flatten)]
    payload_commitments: PayloadCommitments,
    links: Vec<Link>,
    subject_ref: Option<CorrelationIdentifier>,
    principal_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EpistemicType {
    /// Directly observed by the recording system or actor.
    ObservedEvent,
    /// Asserted by an external system of record.
    SystemOfRecordFact,
    /// Asserted by the record's own producer, unverified by the store.
    ProducerClaim,
    /// Asserted by a human, not machine-observed.
    HumanReport,
    /// A judgment or classification reached by interpretation, not direct observation.
    SemanticJudgment,
    /// A value computed or aggregated from other records.
    DerivedMetric,
    /// A ruling on a matter that was disputed or required judgment.
    Adjudication,
    /// A reference to an obligation the record does not itself discharge.
    ObligationReference,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PayloadCommitments {
    #[serde(rename = "payload_commitments")]
    #[serde_as(as = "Vec<digest::Codec>")]
    digests: Vec<Digest>,
    retention_state: RetentionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Link {
    link_type: LinkType,
    #[serde(with = "digest")]
    target: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LinkType {
    /// The carrying record's claim depends on, or is intelligible only with reference to, the
    /// target's committed content. A cites link lifts nothing about the target beyond the target's
    /// own committed claim: it does not inherit whatever the target record itself cites, and a
    /// reader that wants to know what the target's own citations say must resolve them
    /// independently.
    Cites,

    /// The carrying record — necessarily [`EpistemicType::Adjudication`] — renders a judgment about the
    /// target's claim. The judgment covers exactly the target's own committed claim. It does not
    /// extend to claims made inside records the target itself cites; a citing record's adjudication
    /// is not an adjudication of what is cited two hops away.
    Adjudicates,

    /// The carrying record replaces the target's content for current use, without mutating the
    /// target. The target's original commitment stands as part of the store's history; supersedes
    /// is how a store represents a correction as a new fact rather than an edit.
    Supersedes,

    /// The carrying record states that its author has seen and holds the target — establishing
    /// receipt, not agreement.
    Acknowledges,

    /// The carrying record disputes the target's claim.
    Rebuts,

    /// The carrying record — a Close record — binds a stated range or set of records as reconciled.
    Closes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RetentionState {
    /// The payload can be resolved under current policy.
    ///
    /// Resolving the payload returns bytes.
    Available,

    /// Only some fields or preimages remain.
    ///
    /// Resolving the payload returns the remaining fields; the record's own digest still verifies
    /// against what existed at commit time even though full reproduction is no longer possible.
    Partial,

    /// The payload may exist but the requester is not authorized.
    ///
    /// Resolving the payload returns nothing; a policy refusal, not a claim the payload is gone.
    Withheld,

    /// The payload was intentionally destroyed or has expired.
    ///
    /// Resolving the payload returns nothing; commitment integrity survives, semantic
    /// reproducibility does not.
    Deleted,

    /// Deletion is suspended by policy or legal requirement.
    ///
    /// Resolving the payload behaves as [`Available`](Self::Available) or
    /// [`Partial`](Self::Partial) per the payload's actual state; the hold blocks a future
    /// transition to [`Deleted`](Self::Deleted), it does not itself change resolvability.
    LegalHold,
}
