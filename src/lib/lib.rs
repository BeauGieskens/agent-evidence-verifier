#![expect(dead_code, reason = "WIP")]

mod cll;
mod record;
mod request;
mod response;
mod serde;

pub mod protocol;
pub mod semantics;
pub mod signatures;
mod verify;
pub mod wire;

use bytes::Bytes;
use request::EvidenceSubject;
pub use verify::{Error, evaluate_case, verify_response};

type CorrelationIdentifier = String;
type Digest = Bytes;
type Position = u64;
