#![expect(dead_code, reason = "WIP")]

mod cll;
mod record;
mod request;
mod response;

use bytes::Bytes;
use request::EvidenceSubject;

type CorrelationIdentifier = String;
type Digest = Bytes;
type Position = u64;
