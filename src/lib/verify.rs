//! Public entry points for the explicit evidence-request corpus profile.
//!
//! This profile uses SHA-256 text digests and Ed25519/JCS refusals. It is not
//! a claim that the base draft specifies those encodings or an artifact format.

use std::fmt;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{protocol, semantics, signatures};

/// A malformed input or unsupported verification operation.
#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self(message)
    }
}

/// Evaluates input facts independently of the case's expected answer.
///
/// Corpus metadata supplies the draft revision, holdings, and applicable registry.
/// This is separate from verifying a received response: some vectors intentionally
/// supply abstract facts in place of signatures, receipts, or artifact proofs.
pub fn evaluate_case(case: &Value, context: &Value) -> Result<Value, Error> {
    let corpus = context
        .get("corpus")
        .and_then(Value::as_str)
        .ok_or_else(|| Error("missing corpus name".into()))?;
    // Remove expectations before dispatch, including any nested expectations.
    let mut input = case.clone();
    strip_expectations(&mut input);
    let mut context = context.clone();
    if let Some(object) = context.as_object_mut() {
        object.remove("cases");
    }
    strip_expectations(&mut context);
    let result = match corpus {
        "request" | "carriage" | "digest" => protocol::evaluate(corpus, &input, &context),
        "categories" if input.get("kind").and_then(Value::as_str) == Some("request") => {
            protocol::evaluate(corpus, &input, &context)
        }
        "refusal" | "unavailable-window" => signatures::evaluate(corpus, &input, &context),
        "refusal-02" if input.get("facts").is_none() => {
            signatures::evaluate(corpus, &input, &context)
        }
        _ => semantics::evaluate(corpus, &input, &context),
    };
    result.map_err(Error)
}

/// Prevents expected outputs from becoming evaluator inputs.
fn strip_expectations(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("expect");
            for value in object.values_mut() {
                strip_expectations(value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(strip_expectations),
        _ => {}
    }
}

/// Verifies a raw JSON/CBOR refusal against retained request bytes and trust keys.
///
/// Malformed requests can still receive valid refusals, so request validity is
/// reported independently. A verified refusal is not a successful evidence grant.
/// Artifact responses fail closed: this corpus supplies no concrete artifact
/// envelope or proof profile from which to implement their verification.
pub fn verify_response(
    request: &[u8],
    response: &[u8],
    trusted_keys: &[String],
) -> Result<Value, Error> {
    let response = protocol::decode_document(response).map_err(Error)?;
    if response.get("reason").is_none() {
        return Err(Error("unsupported response: expected an Ed25519/JCS refusal; artifact verification requires an explicit evidence-format profile".into()));
    }
    let response = response
        .project_json(&[
            "issued_at",
            "reason",
            "request_digest",
            "key_id",
            "sig",
            "detail",
        ])
        .map_err(Error)?;
    let reasons = [
        "not_authorized",
        "no_such_subject",
        "coverage_unsatisfiable",
        "derivation_unsupported",
        "policy_declined",
        "deadline_unmet",
        "request_malformed",
        "retention_expired",
        "capacity_exceeded",
        "request_unauthenticated",
    ]
    .map(str::to_owned);
    let checks = signatures::verify_refusal(&response, trusted_keys, &reasons).map_err(Error)?;
    let digest = hex::encode(Sha256::digest(request));
    let binding = response.get("request_digest").and_then(Value::as_str) == Some(digest.as_str());
    let accepted = checks.get("conformant").and_then(Value::as_bool) == Some(true) && binding;
    let request_validation = match protocol::decode_document(request) {
        Ok(value) => protocol::validate_request(&value, true),
        Err(_) => json!({"well_formed": false, "reason": "request_malformed"}),
    };
    Ok(json!({
        "profile": "evidence-request-corpus-ed25519-jcs",
        "state": if accepted { "refusal" } else { "invalid_response" },
        "accepted": accepted,
        "request_digest": digest,
        "identifies_request": binding,
        "request_validation": request_validation,
        "signature": checks["signature"],
        "reason_registered": checks["reason_registered"],
        "conformant": checks["conformant"],
        "reason": response["reason"],
    }))
}
