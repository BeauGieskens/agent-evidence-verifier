#![expect(dead_code, reason = "WIP")]

mod cll;
mod record;
mod request;
mod response;
mod serde;

use bytes::Bytes;
use request::EvidenceSubject;

type CorrelationIdentifier = String;
type Digest = Bytes;
type Position = u64;
