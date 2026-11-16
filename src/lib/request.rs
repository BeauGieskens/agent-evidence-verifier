use std::ops::RangeInclusive;

use bytes::Bytes;
use jiff::Timestamp;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};

use crate::{CorrelationIdentifier, Digest, Position, serde::digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EvidenceRequest {
    /// What evidence is asked for.
    subject: EvidenceSubject,
    /// The anchoring constraint the response must satisfy.
    coverage: EvidenceCoverage,
    /// Identifier of a named computation over the subject.
    derivation: Option<DerivationIdentifier>,
    /// Latest useful response time.
    deadline: Option<Timestamp>,
    /// Requester-supplied nonce or timestamp.
    nonce: Option<Nonce>,
    /// Where the requester believes the responder can be reached.
    route: Option<String>,
    /// The evidence categories the requester asks the responder to declare.
    categories: Option<CategoriesRequest>,
}

/// The subject of an evidence request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSubject {
    /// The responder's entire evidence body for this evidence stream.
    FullHistory,
    /// The responder's checkpoints and their receipts for this stream.
    Checkpoints,
    /// The single record identified by this digest.
    #[serde(with = "digest")]
    Record(Digest),
    /// The records covered by the given position range, under the coverage anchor's ordering.
    #[serde(with = "position_range_tuple")]
    Range(RangeInclusive<Position>),
    /// All records the responder holds that carry this correlation identifier.
    Correlation(CorrelationIdentifier),
    /// Every record the responder holds that cites this exchange half.
    #[serde(with = "digest")]
    Exchange(Digest),
}

/// The anchoring constraint that an evidence response must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceCoverage {
    /// The requester already holds, obtained out of band, a specific coverage anchor — for example
    /// a published checkpoint — and requires the response to verify against exactly that anchor.
    /// This is the strongest form: the anchor's integrity does not depend on the responder at all,
    /// because the responder never chose it. A requester's own exchange half is a valid pin for an
    /// exchange subject: the responder's record cites it, and the requester sealed it before the
    /// responder's answer existed.
    #[serde(with = "digest")]
    ExpectedPin(Digest),

    /// The requester holds no specific anchor and instead requires that the response be covered by
    /// a commitment at least this fresh — at least this log size, or issued no earlier than this
    /// time. The responder selects a qualifying anchor and identifies it in the response. This form
    /// trades the pin's independence for availability: the requester can always form the request,
    /// but the anchor's independence now rests on whatever external witnessing or publication that
    /// anchor has, outside this protocol.
    MinFreshness(SizeOrTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum SizeOrTime {
    Size(usize),
    Time(Timestamp),
}

/// A named derivation or a digest of a derivation definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DerivationIdentifier {
    /// Checkpoints, receipts, and consistency proofs for a stream.
    HistoryCard1,
    /// Digest of a derivation definition.
    Other(Digest),
    /// Retained so capability checks can refuse it with `derivation_unsupported` (§3.3).
    UnsupportedToken(String),
}

impl Serialize for DerivationIdentifier {
    /// Emits built-in tokens directly and delegates definition digests to the digest codec.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::HistoryCard1 => serializer.serialize_str("history_card/1"),
            Self::Other(digest) => digest::serialize(digest, serializer),
            Self::UnsupportedToken(token) => serializer.serialize_str(token),
        }
    }
}

impl<'de> Deserialize<'de> for DerivationIdentifier {
    /// Recognizes the built-in token without treating it as an untagged unit value.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum NamedDerivation {
            #[serde(rename = "history_card/1")]
            HistoryCard1,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WireIdentifier {
            Named(NamedDerivation),
            #[serde(with = "digest")]
            Digest(Digest),
            UnsupportedToken(String),
        }

        match WireIdentifier::deserialize(deserializer)? {
            WireIdentifier::Named(NamedDerivation::HistoryCard1) => Ok(Self::HistoryCard1),
            WireIdentifier::Digest(digest) => Ok(Self::Other(digest)),
            WireIdentifier::UnsupportedToken(token) => Ok(Self::UnsupportedToken(token)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum Nonce {
    Timestamp(Timestamp),
    String(String),
    Bytes(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct CategoriesRequest {
    /// Identifier of a category set.
    set: String,
    /// Distinct category names from the requested category set.
    names: NonEmpty<String>,
}

mod position_range_tuple {
    use serde::{Deserializer, Serializer};

    use super::*;

    /// A pair of positions, inclusive, that defines the start and end for a range of records.
    #[derive(Serialize, Deserialize)]
    #[repr(transparent)]
    #[serde(transparent)]
    struct RangeTuple([Position; 2]);

    impl From<&RangeInclusive<Position>> for RangeTuple {
        fn from(range: &RangeInclusive<Position>) -> Self {
            RangeTuple([*range.start(), *range.end()])
        }
    }

    impl From<RangeTuple> for RangeInclusive<Position> {
        fn from(tuple: RangeTuple) -> Self {
            let [start, end] = tuple.0;
            start..=end
        }
    }

    pub fn serialize<S>(range: &RangeInclusive<Position>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let range = RangeTuple::from(range);
        range.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RangeInclusive<Position>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tuple = <[Position; 2]>::deserialize(deserializer)?;
        Ok(RangeTuple(tuple).into())
    }
}
