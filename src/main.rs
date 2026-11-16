//! Offline evidence-request verification and existing-corpus execution.

mod vectors;

use std::{fs, path::PathBuf, process::ExitCode};

use agent_evidence_verifier::{protocol::decode_document, verify_response};
use clap::Parser;
use serde_json::Value;

/// Errors that prevent loading or evaluating CLI inputs.
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Explicit profile inputs; trust never comes from the response itself.
#[derive(Parser)]
#[command(version, about = "Offline Evidence Request corpus-profile verifier")]
struct Args {
    /// Original request bytes, not a parsed and re-serialized request.
    #[arg(required_unless_present = "vectors", conflicts_with = "vectors")]
    request: Option<PathBuf>,
    /// Raw JSON/CBOR response under the corpus's Ed25519/JCS refusal profile.
    #[arg(required_unless_present = "vectors", conflicts_with = "vectors")]
    response: Option<PathBuf>,
    /// JSON array of trusted raw Ed25519 public keys as hex strings.
    #[arg(long, required_unless_present = "vectors", conflicts_with = "vectors")]
    trust: Option<PathBuf>,
    /// Existing evidence-request corpus file or directory with manifest.json.
    #[arg(long, conflicts_with_all = ["request", "response", "trust"])]
    vectors: Option<PathBuf>,
    /// Run one vector by exact id; requires --vectors.
    #[arg(long, requires = "vectors")]
    case: Option<String>,
}

/// Separates verification rejection (1) from usage/input errors (2).
fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

/// Runs a bounded offline operation without network access or background tasks.
fn run(args: Args) -> Result<bool, Error> {
    if let Some(path) = args.vectors {
        return vectors::run(&path, args.case.as_deref());
    }
    let request = args.request.ok_or("missing request path")?;
    let response = args.response.ok_or("missing response path")?;
    let trust = args.trust.ok_or("missing trust path")?;
    let trust = decode_document(&fs::read(trust)?)?;
    let trusted_keys = trust
        .as_array()
        .ok_or("trust file must be a JSON array of hex public keys")?
        .iter()
        .map(|value| {
            let key = value.as_str().ok_or("trust keys must be hex strings")?;
            let bytes =
                hex::decode(key).map_err(|error| format!("invalid trusted public key: {error}"))?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "trusted Ed25519 keys must have 32 bytes")?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|error| format!("invalid trusted public key: {error}"))?;
            Ok(hex::encode(key))
        })
        .collect::<Result<Vec<String>, Error>>()?;
    let result = verify_response(&fs::read(request)?, &fs::read(response)?, &trusted_keys)?;
    let accepted = result.get("accepted").and_then(Value::as_bool) == Some(true);
    println!("{result}");
    Ok(accepted)
}
