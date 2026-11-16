//! Request validation and transport checks for the evidence-request vector profile.
//!
//! SHA-256 always covers retained octets, never a parsed or re-encoded document.
//! Subject and coverage digests remain 32-byte lowercase hex strings. Derivation
//! identifiers use the existing model's enum and generic digest codec. Expected
//! answers and case identifiers are not inputs to any decision here.

use std::collections::BTreeSet;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Shared strict decoders preserving native wire types without reserved markers.
pub use crate::wire::{decode_cbor, decode_document, decode_json};
use crate::{request::DerivationIdentifier, wire::Value as WireValue};

/// Evaluates `request`, `categories`/`request`, `carriage`, or `digest` facts.
///
/// `context` is the corpus document. Its optional boolean `categories_supported`
/// defaults to true. Request cases check every supplied JSON/CBOR binding and
/// reject inconsistent results. Results contain `well_formed` and, on refusal,
/// `reason`; carriage returns `is_request_digest`, `answers`, `accepted`, or
/// `classified_as`; digest returns `request_digest` or `identifies_request`.
/// Exclusion assertions belong to the caller, not this evaluator.
///
/// Invalid request documents yield `request_malformed`. Missing harness facts,
/// unsupported kinds, and invalid harness hex/base64 return an error instead.
pub fn evaluate(corpus: &str, case: &Value, context: &Value) -> Result<Value, String> {
    match corpus {
        "request" => evaluate_request(case, context),
        "categories" if case.get("kind").and_then(Value::as_str) == Some("request") => {
            evaluate_request(case, context)
        }
        "carriage" => evaluate_carriage(case),
        "digest" => {
            let digest = raw_digest(&request_bytes(case)?);
            if let Some(candidate) = case.get("refusal_request_digest") {
                Ok(json!({"identifies_request": digest_matches(candidate, &digest)}))
            } else {
                Ok(json!({"request_digest": digest}))
            }
        }
        _ => Err(format!(
            "unsupported protocol corpus or case kind: {corpus}"
        )),
    }
}

/// Checks a decoded request under the corpus's explicit wire conventions.
///
/// Unknown request, coverage, and category members are ignored without converting
/// their native values to JSON. Repeated known members are malformed. Unsupported
/// categories are ignored even when malformed. Known coverage values are checked
/// before requiring exactly one coverage alternative. Derivation validation uses
/// the model's enum deserializer; nonces accept native text or byte strings only.
/// Success omits `reason`; failure uses an exact protocol refusal token.
pub fn validate_request(value: &WireValue, categories_supported: bool) -> Value {
    match request_reason(value, categories_supported) {
        Some(reason) => json!({"well_formed": false, "reason": reason}),
        None => json!({"well_formed": true}),
    }
}

/// Checks syntax first so malformed fields cannot hide behind coverage errors.
fn request_reason(value: &WireValue, categories_supported: bool) -> Option<&'static str> {
    let malformed = Some("request_malformed");
    let Some(request) = value.as_map() else {
        return malformed;
    };
    if repeated_known_fields(
        request,
        &[
            "subject",
            "coverage",
            "derivation",
            "deadline",
            "nonce",
            "route",
            "categories",
        ],
    ) || !value.get("subject").is_some_and(valid_subject)
        || value
            .get("derivation")
            .is_some_and(|v| !valid_derivation(v))
        || value
            .get("deadline")
            .is_some_and(|v| !valid_wire_timestamp(v))
        || value.get("route").is_some_and(|v| !v.is_string())
        || value.get("nonce").is_some_and(|v| !valid_nonce(v))
        || (categories_supported
            && value
                .get("categories")
                .is_some_and(|v| !valid_categories(v)))
    {
        return malformed;
    }
    let Some(coverage) = value.get("coverage") else {
        return Some("coverage_unsatisfiable");
    };
    let Some(entries) = coverage.as_map() else {
        return malformed;
    };
    if repeated_known_fields(entries, &["expected_pin", "min_freshness"]) {
        return malformed;
    }
    let pin = coverage.get("expected_pin");
    let freshness = coverage.get("min_freshness");
    if pin.is_some_and(|v| !is_profile_digest(v))
        || freshness.is_some_and(|v| v.as_u64().is_none() && !valid_wire_timestamp(v))
    {
        return malformed;
    }
    if pin.is_some() == freshness.is_some() {
        Some("coverage_unsatisfiable")
    } else {
        None
    }
}

/// Detects repeated understood text keys while leaving unknown native keys alone.
fn repeated_known_fields(entries: &[(WireValue, WireValue)], names: &[&str]) -> bool {
    let mut seen = BTreeSet::new();
    entries.iter().any(|(key, _)| {
        key.as_str()
            .is_some_and(|key| names.contains(&key) && !seen.insert(key))
    })
}

/// Recognizes the six single-member subject maps, including ordered ranges.
fn valid_subject(value: &WireValue) -> bool {
    let Some(subject) = value.as_map().filter(|v| v.len() == 1) else {
        return false;
    };
    let Some((form, content)) = subject.iter().next() else {
        return false;
    };
    match form.as_str() {
        Some("full_history" | "checkpoints") => content.is_null(),
        Some("record" | "exchange") => is_profile_digest(content),
        Some("correlation") => content.is_string(),
        Some("range") => content.as_array().is_some_and(|pair| {
            matches!(pair.as_slice(), [a, b] if matches!(
                (a.as_u64(), b.as_u64()), (Some(start), Some(end)) if start <= end
            ))
        }),
        _ => false,
    }
}

/// Recognizes only the local SHA-256 profile, not arbitrary generic digests.
fn is_profile_digest(value: &WireValue) -> bool {
    value.as_str().is_some_and(profile_digest_text)
}

/// Checks the unchanged lowercase SHA-256 text convention across input types.
fn profile_digest_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Delegates named variants and generic hex digests to the existing model.
fn valid_derivation(value: &WireValue) -> bool {
    value.as_str().is_some_and(|text| {
        let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(text);
        DerivationIdentifier::deserialize(deserializer).is_ok()
    })
}

/// Adapts only native timestamp text to the shared JSON-facing validator.
fn valid_wire_timestamp(value: &WireValue) -> bool {
    value
        .as_str()
        .is_some_and(|text| valid_timestamp(&Value::String(text.to_owned())))
}

/// Checks an RFC 3339 instant without using wall-clock time or a local zone.
pub fn valid_timestamp(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        let bytes = s.as_bytes();
        if bytes.len() < 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || !matches!(bytes[10], b'T' | b't')
            || bytes[13] != b':'
            || bytes[16] != b':'
            || !bytes[..19]
                .iter()
                .enumerate()
                .all(|(index, b)| matches!(index, 4 | 7 | 10 | 13 | 16) || b.is_ascii_digit())
        {
            return false;
        }
        let mut suffix = &bytes[19..];
        if suffix.first() == Some(&b'.') {
            suffix = &suffix[1..];
            let digits = suffix.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return false;
            }
            suffix = &suffix[digits..];
        }
        let offset = matches!(suffix, [b'Z' | b'z'])
            || matches!(suffix, [b'+' | b'-', h1, h2, b':', m1, m2]
                if [h1, h2, m1, m2].iter().all(|b| b.is_ascii_digit()));
        offset && s.parse::<jiff::Timestamp>().is_ok()
    })
}

/// Accepts native text and CBOR byte strings, never map-based byte imitations.
fn valid_nonce(value: &WireValue) -> bool {
    matches!(value, WireValue::Text(_) | WireValue::Bytes(_))
}

/// Requires a set identifier and nonempty distinct textual category names.
fn valid_categories(value: &WireValue) -> bool {
    let Some(categories) = value.as_map() else {
        return false;
    };
    if repeated_known_fields(categories, &["set", "names"]) {
        return false;
    }
    let Some(names) = value.get("names").and_then(WireValue::as_array) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    value.get("set").is_some_and(WireValue::is_string)
        && !names.is_empty()
        && names
            .iter()
            .all(|name| name.as_str().is_some_and(|name| seen.insert(name)))
}

/// Validates each supplied binding without allowing one to mask the other.
fn evaluate_request(case: &Value, context: &Value) -> Result<Value, String> {
    let categories_supported = match context.get("categories_supported") {
        Some(value) => value
            .as_bool()
            .ok_or("categories_supported must be boolean")?,
        None => true,
    };
    let mut results = Vec::new();
    if let Some(source) = case.get("request_json") {
        let source = source.as_str().ok_or("request_json must be text")?;
        results.push(validate_decoded(
            decode_json(source.as_bytes()),
            categories_supported,
        ));
    }
    if let Some(source) = case.get("request_cbor_hex") {
        let source = source.as_str().ok_or("request_cbor_hex must be text")?;
        let bytes = hex::decode(source).map_err(|e| format!("invalid request_cbor_hex: {e}"))?;
        results.push(validate_decoded(decode_cbor(&bytes), categories_supported));
    }
    let result = results
        .first()
        .ok_or("missing request_json or request_cbor_hex")?;
    if results.iter().any(|other| other != result) {
        return Err("JSON and CBOR request bindings disagree".to_owned());
    }
    Ok(result.clone())
}

/// Converts decoding failures into protocol malformation rather than harness errors.
fn validate_decoded(document: Result<WireValue, String>, categories_supported: bool) -> Value {
    match document {
        Ok(value) => validate_request(&value, categories_supported),
        Err(_) => json!({"well_formed": false, "reason": "request_malformed"}),
    }
}

/// Selects raw request octets using the declared encoding when present.
fn request_bytes(case: &Value) -> Result<Vec<u8>, String> {
    match case.get("encoding").and_then(Value::as_str) {
        Some("json") => Ok(text(case, "request_json")?.as_bytes().to_vec()),
        Some("cbor") => hex_bytes(case, "request_cbor_hex"),
        Some(encoding) => Err(format!("unsupported request encoding: {encoding}")),
        None if case.get("request_json").is_some() => {
            Ok(text(case, "request_json")?.as_bytes().to_vec())
        }
        None => hex_bytes(case, "request_cbor_hex"),
    }
}

/// Evaluates carriage facts independently of any declared digest derivation hint.
fn evaluate_carriage(case: &Value) -> Result<Value, String> {
    match text(case, "kind")? {
        "digest" => {
            let bytes = carried_bytes(text(case, "carriage")?, text(case, "carried_text")?)?;
            Ok(json!({"is_request_digest": digest_matches(
                member(case, "candidate_digest")?, &raw_digest(&bytes)
            )}))
        }
        "binding" => {
            let digest = raw_digest(&hex_bytes(case, "retained_request_hex")?);
            Ok(
                json!({"answers": digest_matches(member(case, "envelope_request_digest")?, &digest)}),
            )
        }
        "media_type" => Ok(json!({"accepted": accepted_media_type(text(case, "media_type")?)})),
        "classify" => Ok(json!({"classified_as": classify(member(case, "received")?)?})),
        kind => Err(format!("unsupported carriage kind: {kind}")),
    }
}

/// Classifies transport shape only; error flags and prose never imply a refusal.
fn classify(received: &Value) -> Result<&'static str, String> {
    let request_media_type = text(received, "request_media_type")?;
    let matching_media = |value: &Value| {
        accepted_media_type(request_media_type)
            && value.get("media_type").and_then(Value::as_str) == Some(request_media_type)
    };
    match text(received, "carriage")? {
        "a2a" => {
            let reply = received
                .get("reply_artifact")
                .and_then(|v| v.get("parts"))
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    matches!(parts.as_slice(), [part] if
                        part.get("kind").and_then(Value::as_str) == Some("raw")
                        && matching_media(part))
                });
            if reply {
                Ok("reply")
            } else if matches!(
                received.get("task_state").and_then(Value::as_str),
                Some("TASK_STATE_WORKING" | "TASK_STATE_UNSPECIFIED")
            ) {
                Ok("pending")
            } else {
                Ok("no_reply")
            }
        }
        "mcp" => {
            let reply = received.get("structured_content").is_some_and(|content| {
                matching_media(content)
                    && content
                        .get("reply")
                        .and_then(Value::as_str)
                        .is_some_and(|reply| URL_SAFE_NO_PAD.decode(reply).is_ok())
            });
            Ok(if reply { "reply" } else { "no_reply" })
        }
        carriage => Err(format!("unsupported carriage: {carriage}")),
    }
}

/// Compares media types exactly, without case folding or parameter stripping.
fn accepted_media_type(media_type: &str) -> bool {
    matches!(media_type, "application/json" | "application/cbor")
}

/// Decodes each binding's exact alphabet, padding, and canonical trailing bits.
fn carried_bytes(carriage: &str, text: &str) -> Result<Vec<u8>, String> {
    let result = match carriage {
        "a2a" => STANDARD.decode(text),
        "mcp" => URL_SAFE_NO_PAD.decode(text),
        _ => return Err(format!("unsupported carriage: {carriage}")),
    };
    result.map_err(|e| format!("invalid {carriage} base64: {e}"))
}

/// Hashes only the original bytes and emits the profile's lowercase hex form.
fn raw_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Requires profile syntax as well as equality to a computed request digest.
fn digest_matches(candidate: &Value, digest: &str) -> bool {
    candidate
        .as_str()
        .is_some_and(|text| profile_digest_text(text) && text == digest)
}

/// Reads a required harness member without conflating absence with JSON null.
fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("missing member: {name}"))
}

/// Reads a required harness text member.
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    member(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be text"))
}

/// Decodes retained raw hex without applying digest-length constraints.
fn hex_bytes(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    hex::decode(text(value, name)?).map_err(|e| format!("invalid {name}: {e}"))
}
