//! Offline checks for the evidence-request corpus's Ed25519/JCS profile.
//!
//! Corpus evaluation pins public fixture keys, never private seeds or keys supplied
//! by a signed object. Live callers must supply their own trust anchors through
//! [`verify_refusal`]. Receipt independence and checkpoint coverage are input
//! facts (`accepted`), not cryptographic receipt proofs verified by this module.

use ed25519_dalek::{Signature, VerifyingKey};
use jiff::Timestamp;
use serde_json::{Map, Value, json};

use crate::protocol;

/// Public responder key fixed by the refusal and unavailable-window corpora.
const CORPUS_KEY: &str = "e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117";
/// Public trust anchor of the separately imported interoperability fixture.
const IMPORTED_KEY: &str = "1a965c7d75b9a6b82aea451a40c7de9b770933afb1297d7803b83254b208a863";
/// Refusal registry shared by revisions -00 and -01.
const REASONS: &[&str] = &[
    "not_authorized",
    "no_such_subject",
    "coverage_unsatisfiable",
    "derivation_unsupported",
    "policy_declined",
    "deadline_unmet",
    "request_malformed",
    "retention_expired",
];
/// Understood refusal members compared across transport representations.
const REFUSAL_MEMBERS: &[&str] = &[
    "issued_at",
    "reason",
    "request_digest",
    "key_id",
    "sig",
    "detail",
];
/// Closed vocabulary for unavailable-window statements.
const WINDOW_REASONS: &[&str] = &["flood", "maintenance", "outage", "other_declared"];

/// Computes signature or unavailable-window results without consulting `expect`.
///
/// Supports `refusal`, signature cases in `refusal-02`, and `unavailable-window`.
/// `context` is the full corpus document; -02's `refusal_reasons` supplies its
/// registry. Fixture trust is pinned independently of context keys and seeds.
/// For file cases, the runner must load the same-directory imported file into
/// `case.refusal`. This module neither reads files nor embeds fixture sources.
/// JSON objects and supplied CBOR/JSON refusal frames must agree on understood
/// refusal members; unknown extensions remain opaque and are ignored. Exclusion
/// assertions (`must_not_show_as`) remain the caller's responsibility.
/// Unsupported cases, malformed frame encodings and invalid harness inputs fail
/// with an error; invalid signatures and malformed signed members yield results.
pub fn evaluate(corpus: &str, case: &Value, context: &Value) -> Result<Value, String> {
    match corpus {
        "refusal" | "refusal-02" => {
            if case.get("facts").is_some() {
                return Err("refusal facts require semantic evaluation".to_owned());
            }
            let refusal = refusal_frame(case)?;
            let mut reasons: Vec<String> = REASONS.iter().map(|s| (*s).to_owned()).collect();
            if corpus == "refusal-02" {
                reasons = context
                    .get("refusal_reasons")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "refusal-02 requires refusal_reasons registry".to_owned())?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| "refusal_reasons entries must be text".to_owned())
                    })
                    .collect::<Result<_, _>>()?;
            }
            verify_refusal(
                &refusal,
                &[CORPUS_KEY.to_owned(), IMPORTED_KEY.to_owned()],
                &reasons,
            )
        }
        "unavailable-window" => match text(case, "kind")? {
            "statement" => recognize_statement(case, text(case, "responder_key")?),
            "display" => display_absence(case),
            kind => Err(format!("unsupported unavailable-window kind: {kind}")),
        },
        _ => Err(format!("unsupported signature corpus: {corpus}")),
    }
}

/// Verifies a refusal using only caller-supplied trusted public keys and reasons.
///
/// Returns `signature` (`valid` or `invalid`), `reason_registered`, and
/// `conformant`. An untrusted key always yields `invalid` and cannot conform,
/// even when its signature is mathematically correct. Empty trust accepts none.
/// Keys, signatures and SHA-256 request digests use exact lowercase hex.
///
/// JCS covers precisely the present members among `issued_at`, `reason`, and
/// `request_digest`. Missing or ill-typed members may therefore still have a
/// valid signature, but never form a conforming refusal. Optional `detail` is
/// unsigned; when present it must be text. This verifies neither request binding
/// nor freshness: the caller must compare the digest to retained request bytes
/// and apply its own issuance/replay policy before accepting a live response.
pub fn verify_refusal(
    refusal: &Value,
    trusted_keys: &[String],
    reasons: &[String],
) -> Result<Value, String> {
    let signature = signed_by(
        refusal,
        &["issued_at", "reason", "request_digest"],
        trusted_keys,
    )?;
    let registered = refusal
        .get("reason")
        .and_then(Value::as_str)
        .is_some_and(|reason| reasons.iter().any(|known| known == reason));
    let issued_at = timestamp(refusal, "issued_at").is_some();
    let digest = refusal
        .get("request_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| lowercase_hex(digest, 32));
    let detail = match refusal.get("detail") {
        None => true,
        Some(value) => value.is_string(),
    };
    Ok(json!({
        "signature": if signature { "valid" } else { "invalid" },
        "reason_registered": registered,
        "conformant": signature && registered && issued_at && digest && detail,
    }))
}

/// Reads a mandatory text field from harness input.
fn text<'a>(value: &'a Value, member: &str) -> Result<&'a str, String> {
    value
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{member} must be present and text"))
}

/// Validates protocol timestamp syntax before parsing an instant for comparison.
fn timestamp(value: &Value, member: &str) -> Option<Timestamp> {
    let value = value.get(member)?;
    if !protocol::valid_timestamp(value) {
        return None;
    }
    value.as_str()?.parse().ok()
}

/// Recognizes the profile's exact lowercase hexadecimal encoding and length.
fn lowercase_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verifies only selected present members, independently of schema conformance.
fn signed_by(value: &Value, members: &[&str], trusted: &[String]) -> Result<bool, String> {
    let Some(object) = value.as_object() else {
        return Ok(false);
    };
    let Some(key) = object.get("key_id").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(sig) = object.get("sig").and_then(Value::as_str) else {
        return Ok(false);
    };
    if !trusted.iter().any(|anchor| anchor == key)
        || !lowercase_hex(key, 32)
        || !lowercase_hex(sig, 64)
    {
        return Ok(false);
    }
    let key_bytes = hex::decode(key).map_err(|error| format!("key hex: {error}"))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must have 32 bytes".to_owned())?;
    let Ok(key) = VerifyingKey::from_bytes(&key_array) else {
        return Ok(false);
    };
    let sig_bytes = hex::decode(sig).map_err(|error| format!("signature hex: {error}"))?;
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return Ok(false);
    };
    let mut body = Map::new();
    for member in members {
        if let Some(content) = object.get(*member) {
            body.insert((*member).to_owned(), content.clone());
        }
    }
    let bytes = serde_jcs::to_vec(&Value::Object(body))
        .map_err(|error| format!("cannot canonicalize signing body: {error}"))?;
    Ok(key.verify_strict(&bytes, &signature).is_ok())
}

/// Projects understood refusal members before comparing transport representations.
///
/// Unknown native extensions need not be representable as JSON. Shared decoders
/// reject trailing data; projection rejects duplicate understood members.
fn refusal_frame(case: &Value) -> Result<Value, String> {
    let mut frame = case.get("refusal").map(|refusal| {
        if let Some(object) = refusal.as_object() {
            Value::Object(
                object
                    .iter()
                    .filter(|(key, _)| REFUSAL_MEMBERS.contains(&key.as_str()))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            )
        } else {
            refusal.clone()
        }
    });
    if case.get("file").is_some() && frame.is_none() {
        return Err("file case requires runner-populated refusal".to_owned());
    }
    if let Some(json_frame) = case.get("refusal_json") {
        let decoded = protocol::decode_json(
            json_frame
                .as_str()
                .ok_or_else(|| "refusal_json must be text".to_owned())?
                .as_bytes(),
        )
        .and_then(|value| value.project_json(REFUSAL_MEMBERS))
        .map_err(|error| format!("invalid JSON refusal frame: {error}"))?;
        merge_frame(&mut frame, decoded)?;
    }
    if let Some(cbor_frame) = case.get("refusal_cbor_hex") {
        let bytes = hex::decode(
            cbor_frame
                .as_str()
                .ok_or_else(|| "refusal_cbor_hex must be text".to_owned())?,
        )
        .map_err(|error| format!("invalid CBOR refusal hex: {error}"))?;
        let decoded = protocol::decode_cbor(&bytes)
            .and_then(|value| value.project_json(REFUSAL_MEMBERS))
            .map_err(|error| format!("invalid CBOR refusal frame: {error}"))?;
        merge_frame(&mut frame, decoded)?;
    }
    frame.ok_or_else(|| "case has no refusal object or supported frame".to_owned())
}

/// Requires equivalent understood members when a vector supplies multiple bindings.
fn merge_frame(frame: &mut Option<Value>, decoded: Value) -> Result<(), String> {
    if frame.as_ref().is_some_and(|existing| existing != &decoded) {
        return Err("refusal frame representations disagree".to_owned());
    }
    *frame = Some(decoded);
    Ok(())
}

/// Recognizes a well-formed, responder-signed, independently registered window.
fn recognize_statement(case: &Value, responder: &str) -> Result<Value, String> {
    let statement = case
        .get("statement")
        .ok_or_else(|| "missing statement".to_owned())?;
    let well_formed = matches!(
        (timestamp(statement, "start"), timestamp(statement, "end")),
        (Some(start), Some(end)) if start <= end
    ) && statement
        .get("reason_class")
        .and_then(Value::as_str)
        .is_some_and(|reason| WINDOW_REASONS.contains(&reason));
    if !well_formed {
        return Ok(json!({"recognized": false, "why": "malformed"}));
    }
    if !signed_by(
        statement,
        &["end", "reason_class", "start"],
        &[responder.to_owned()],
    )? {
        return Ok(json!({"recognized": false, "why": "not_signed_by_responder"}));
    }
    let receipts = case
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or_else(|| "receipts must be an array".to_owned())?;
    let earliest = receipts
        .iter()
        .filter(|receipt| receipt.get("accepted").and_then(Value::as_bool) == Some(true))
        .filter_map(|receipt| Some((timestamp(receipt, "time")?, receipt.get("time")?.as_str()?)))
        .min_by_key(|(instant, _)| *instant);
    match earliest {
        Some((_, time)) => Ok(json!({
            "recognized": true,
            "registration_time": time,
            "shown_reason": statement["reason_class"],
        })),
        None => Ok(json!({"recognized": false, "why": "not_registered"})),
    }
}

/// Displays overlapping recognized windows without changing the exchange state.
fn display_absence(case: &Value) -> Result<Value, String> {
    let absence = case
        .get("absence")
        .ok_or_else(|| "missing absence".to_owned())?;
    let received = text(absence, "received")?;
    let state = match received {
        "refusal" => "refusal",
        "nothing" if absence.get("closed_at").is_some_and(Value::is_null) => "pending",
        "nothing" => "recorded_absence",
        _ => return Err(format!("unsupported absence received fact: {received}")),
    };
    let mut covered = Vec::new();
    let mut labels = Map::new();
    if state == "recorded_absence" {
        let sent =
            timestamp(absence, "sent_at").ok_or_else(|| "invalid absence sent_at".to_owned())?;
        let closed = timestamp(absence, "closed_at")
            .ok_or_else(|| "invalid absence closed_at".to_owned())?;
        if closed < sent {
            return Err("absence closed_at precedes sent_at".to_owned());
        }
        let responder = text(case, "responder_key")?;
        let statements = case
            .get("statements")
            .and_then(Value::as_array)
            .ok_or_else(|| "statements must be an array".to_owned())?;
        for entry in statements {
            let recognized = recognize_statement(entry, responder)?;
            if recognized.get("recognized").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let statement = &entry["statement"];
            let (Some(start), Some(end)) =
                (timestamp(statement, "start"), timestamp(statement, "end"))
            else {
                return Err("recognized statement has invalid times".to_owned());
            };
            if start > closed || end < sent {
                continue;
            }
            let id = text(entry, "id")?;
            let registration = timestamp(&recognized, "registration_time")
                .ok_or_else(|| "recognized statement has invalid registration_time".to_owned())?;
            if labels.contains_key(id) {
                return Err(format!("duplicate covering statement id: {id}"));
            }
            covered.push(id.to_owned());
            labels.insert(
                id.to_owned(),
                json!({
                    "reason_class": statement["reason_class"],
                    "registration_time": recognized["registration_time"],
                    "stated_afterwards": registration > closed,
                    "stated_period": [statement["start"], statement["end"]],
                }),
            );
        }
    }
    let mut result = json!({
        "state": state,
        "shown_as": if covered.is_empty() { state } else { "no answer; holder states unavailability" },
        "covered_by": covered,
        "labels": labels,
    });
    if state == "recorded_absence"
        && absence.get("retention_commitment").and_then(Value::as_str) == Some("in_force")
    {
        result["retention_classification"] = json!("attributable_absence");
    }
    Ok(result)
}
