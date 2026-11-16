//! Semantic evaluation of the local evidence-request vector profile.
//!
//! Inputs are case facts and the full corpus document, never expected answers.
//! This module checks resolution and classifications, not artifact proofs or
//! refusal signatures. Unsupported formats and insufficient facts are errors,
//! rather than negative evidence. Exclusion assertions belong to the runner.

use jiff::Timestamp;
use serde_json::{Value, json};

use crate::protocol;

/// Evaluates one supported semantic case against its full corpus context.
///
/// Supported corpora are `resolution`, `carries`, `outcomes`, `invariance`,
/// `retention`, `categories` with kind `invariance`, and `refusal-02` facts.
/// Protocol refusals are successful evaluations with an `answer` and `reason`;
/// malformed harness inputs and unsupported operations return an error.
/// The corpus's `draft` controls refusal registration and retention rules.
pub fn evaluate(corpus: &str, case: &Value, context: &Value) -> Result<Value, String> {
    match corpus {
        "resolution" => resolve(case, context),
        "carries" => record_designation(
            text(case, "record_format")?,
            member(case, "record")?,
            member(case, "subject")?,
        ),
        "outcomes" => Ok(json!({
            "state": outcome_state(member(case, "facts")?, draft(context)?)?
        })),
        "invariance" => Ok(json!({
            "invariance": check_invariance(member(case, "observations")?)?
        })),
        "categories" if case.get("kind").and_then(Value::as_str) == Some("invariance") => {
            Ok(json!({
                "invariance": check_invariance(member(case, "observations")?)?
            }))
        }
        "retention" => {
            if let Some(commitment) = case.get("commitment") {
                Ok(json!({"well_formed": commitment_well_formed(commitment)}))
            } else {
                retention_facts(member(case, "facts")?, draft(context)?)
            }
        }
        "refusal-02" => refusal_facts(member(case, "facts")?, draft(context)?),
        _ => Err(format!(
            "unsupported semantic corpus or case kind: {corpus}"
        )),
    }
}

/// Reads a required member without treating missing data as JSON null.
fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("missing member: {name}"))
}

/// Reads a required text member from harness input.
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    member(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be text"))
}

/// Reads the declared revision, rejecting unknown revisions rather than guessing.
fn draft(context: &Value) -> Result<&str, String> {
    let revision = text(context, "draft")?;
    match revision {
        "draft-mih-agent-evidence-request-00"
        | "draft-mih-agent-evidence-request-01"
        | "draft-mih-agent-evidence-request-02" => Ok(revision),
        _ => Err(format!("unsupported evidence-request draft: {revision}")),
    }
}

/// Recognizes the corpus profile's SHA-256 digest representation.
pub fn is_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Validates the six single-member subject forms and returns the form and value.
///
/// Errors use the protocol token `request_malformed`. Digests follow the local
/// lowercase SHA-256 convention; ranges are inclusive unsigned ordered pairs.
pub fn subject_form(subject: &Value) -> Result<(&str, &Value), String> {
    let malformed = || "request_malformed".to_owned();
    let object = subject.as_object().ok_or_else(malformed)?;
    if object.len() != 1 {
        return Err(malformed());
    }
    let (form, content) = object.iter().next().ok_or_else(malformed)?;
    let valid = match form.as_str() {
        "full_history" | "checkpoints" => content.is_null(),
        "record" | "exchange" => is_digest(content),
        "correlation" => content.is_string(),
        "range" => content.as_array().is_some_and(|pair| {
            matches!(pair.as_slice(), [a, b] if matches!(
                (a.as_u64(), b.as_u64()), (Some(start), Some(end)) if start <= end
            ))
        }),
        _ => false,
    };
    if valid {
        Ok((form, content))
    } else {
        Err(malformed())
    }
}

/// Reports whether a reason belongs to the specified draft's fixed registry.
///
/// Only -02 registers `capacity_exceeded` and `request_unauthenticated`.
/// Unknown drafts have no recognized reasons; evaluators reject them explicitly.
pub fn reason_registered(reason: &str, revision: &str) -> bool {
    let known_draft = matches!(
        revision,
        "draft-mih-agent-evidence-request-00"
            | "draft-mih-agent-evidence-request-01"
            | "draft-mih-agent-evidence-request-02"
    );
    known_draft
        && (matches!(
            reason,
            "not_authorized"
                | "no_such_subject"
                | "coverage_unsatisfiable"
                | "derivation_unsupported"
                | "policy_declined"
                | "deadline_unmet"
                | "request_malformed"
                | "retention_expired"
        ) || (revision == "draft-mih-agent-evidence-request-02"
            && matches!(reason, "capacity_exceeded" | "request_unauthenticated")))
}

/// Applies designated record fields, never substring search across arbitrary data.
///
/// The local profile designates evidence-layer `subject_ref` for correlation,
/// and capsule references with purpose `counterparty_half` for exchange halves.
/// Other format/subject combinations are unchecked, represented by an error.
pub fn record_designation(format: &str, record: &Value, subject: &Value) -> Result<Value, String> {
    let (form, content) = subject_form(subject)?;
    if !record.is_object() {
        return Err("record must be an object".to_owned());
    }
    match (format, form) {
        ("evidence-layer", "correlation") => Ok(json!({
            "carries": record.get("subject_ref") == Some(content)
        })),
        ("capsule", "exchange") => {
            let cites = match record.get("references") {
                None => false,
                Some(references) => references
                    .as_array()
                    .ok_or_else(|| "references must be an array".to_owned())?
                    .iter()
                    .any(|reference| {
                        reference.get("citation_purpose").and_then(Value::as_str)
                            == Some("counterparty_half")
                            && reference.get("digest") == Some(content)
                    }),
            };
            Ok(json!({"cites": cites}))
        }
        _ => Err(format!("unchecked record designation: {format}/{form}")),
    }
}

/// Classifies received evidence without manufacturing a refusal from silence.
///
/// Verification and signature fields are supplied facts, not cryptographic
/// checks. An invalid signature is insufficient to classify a signed refusal
/// in this corpus profile and therefore returns an error.
pub fn outcome_state<'a>(facts: &'a Value, revision: &str) -> Result<&'a str, String> {
    match text(facts, "received")? {
        "artifact" => match text(facts, "artifact_verification")? {
            "verified" => Ok("artifact_verified"),
            "failed" => Ok("artifact_verification_failed"),
            other => Err(format!("unsupported artifact verification: {other}")),
        },
        "refusal" => {
            if text(facts, "refusal_signature")? != "valid" {
                return Err("refusal signature is not verified".to_owned());
            }
            if reason_registered(text(facts, "refusal_reason")?, revision) {
                Ok("refusal")
            } else {
                Ok("refusal_nonconformant")
            }
        }
        "nothing" | "transport_error" | "subprotocol_not_offered" => match text(facts, "window")? {
            "open" => Ok("pending"),
            "closed" => Ok("recorded_absence"),
            other => Err(format!("unsupported waiting window: {other}")),
        },
        other => Err(format!("unsupported received evidence: {other}")),
    }
}

/// Classifies a registered refusal against an in-force, lapsed, or absent promise.
///
/// The -00 literal breach table is preserved, including `retention_expired`
/// inside the promise and `no_such_subject` after it. The two -02 reasons are
/// exempt only in -02; an unregistered reason is not silently treated as exempt.
pub fn classify_retention(
    commitment: &str,
    reason: &str,
    revision: &str,
) -> Result<&'static str, String> {
    if !reason_registered(reason, revision) {
        return Err(format!(
            "unregistered refusal reason for {revision}: {reason}"
        ));
    }
    let exempt = matches!(
        reason,
        "not_authorized"
            | "coverage_unsatisfiable"
            | "derivation_unsupported"
            | "request_malformed"
            | "capacity_exceeded"
            | "request_unauthenticated"
    );
    match commitment {
        "in_force" => Ok(if exempt { "no_breach" } else { "breach" }),
        "lapsed" => Ok(match reason {
            "no_such_subject" => "wrong_token",
            "retention_expired" => "correct",
            _ => "no_breach",
        }),
        "none" => Ok("no_breach"),
        other => Err(format!("unsupported retention commitment state: {other}")),
    }
}

/// Validates legacy retention commitment syntax, not its signature or coverage.
///
/// The local -00 corpus permits record/exchange digests or positional ranges,
/// but not correlation, full-history, or checkpoint subjects. No coverage field
/// is invented for that legacy wire shape. Expiration must be a valid timestamp.
pub fn commitment_well_formed(commitment: &Value) -> bool {
    commitment
        .get("evidence_stream")
        .is_some_and(Value::is_string)
        && commitment
            .get("until")
            .is_some_and(protocol::valid_timestamp)
        && commitment.get("subject").is_some_and(|subject| {
            matches!(
                subject_form(subject),
                Ok(("record" | "exchange" | "range", _))
            )
        })
}

/// Evaluates refusal or absence facts in the retention table.
fn retention_facts(facts: &Value, revision: &str) -> Result<Value, String> {
    let commitment = text(facts, "commitment")?;
    if facts.get("received").is_some() {
        if !matches!(commitment, "in_force" | "lapsed" | "none") {
            return Err(format!(
                "unsupported retention commitment state: {commitment}"
            ));
        }
        let state = outcome_state(facts, revision)?;
        if state != "recorded_absence" {
            return Err(format!(
                "retention absence case is not a recorded absence: {state}"
            ));
        }
        Ok(json!({
            "classification": if commitment == "in_force" {
                "attributable_absence"
            } else {
                "attempt_only"
            },
            "state": state
        }))
    } else {
        Ok(json!({
            "classification": classify_retention(
                commitment, text(facts, "refusal_reason")?, revision
            )?
        }))
    }
}

/// Maps -02 facts to retention, operational refusal reasons, or illustrative status.
fn refusal_facts(facts: &Value, revision: &str) -> Result<Value, String> {
    if facts.get("commitment").is_some() {
        return retention_facts(facts, revision);
    }
    if let Some(cause) = facts.get("cause") {
        return match cause.as_str() {
            Some("responder_load") if reason_registered("capacity_exceeded", revision) => {
                Ok(json!({"reason": "capacity_exceeded"}))
            }
            _ => Err(format!("unsupported refusal cause for {revision}: {cause}")),
        };
    }
    let reason = text(facts, "refusal_reason")?;
    if !reason_registered(reason, revision) {
        return Err(format!(
            "unregistered refusal reason for {revision}: {reason}"
        ));
    }
    Ok(json!({
        "status_unknown": true,
        "withheld_by_policy": matches!(reason, "not_authorized" | "policy_declined"),
        "evidence_of_non_satisfaction": false
    }))
}

/// A validated observation retaining artifact bytes separately from request inputs.
struct Observation<'a> {
    /// Original fields supply the resolved anchor and optional responder identity.
    source: &'a Value,
    /// Request inputs determine whether two observations are comparable.
    request: &'a Value,
    /// Raw bytes prevent equivalent JSON serializations from hiding divergence.
    artifact: Vec<u8>,
}

/// Compares all comparable pairs, returning holds, violated, or not_comparable.
///
/// Comparability requires the same responder (when supplied), subject, selected
/// anchor, derivation, and categories. Nonce, route, requester, transport, and
/// verification material are irrelevant. Category-name order is retained:
/// the local draft vectors deliberately leave its meaning unspecified.
pub fn check_invariance(observations: &Value) -> Result<&'static str, String> {
    let values = observations
        .as_array()
        .ok_or_else(|| "observations must be an array".to_owned())?;
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let request = member(value, "request")?;
        subject_form(member(request, "subject")?)?;
        if !is_digest(member(value, "resolved_anchor")?) {
            return Err("resolved_anchor must be a digest".to_owned());
        }
        let artifact = decode_hex(text(value, "artifact_hex")?)?;
        parsed.push(Observation {
            source: value,
            request,
            artifact,
        });
    }
    let mut comparable = false;
    for (index, left) in parsed.iter().enumerate() {
        for right in parsed.iter().skip(index + 1) {
            if same_artifact_inputs(left, right) {
                comparable = true;
                if left.artifact != right.artifact {
                    return Ok("violated");
                }
            }
        }
    }
    Ok(if comparable {
        "holds"
    } else {
        "not_comparable"
    })
}

/// Matches only semantic artifact inputs, not transport or requester properties.
fn same_artifact_inputs(left: &Observation<'_>, right: &Observation<'_>) -> bool {
    ["resolved_anchor", "responder", "evidence_stream"]
        .iter()
        .all(|key| left.source.get(*key) == right.source.get(*key))
        && ["subject", "derivation", "categories"]
            .iter()
            .all(|key| left.request.get(*key) == right.request.get(*key))
}

/// Decodes hex bytes without parsing or reserializing the represented artifact.
fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    hex::decode(encoded).map_err(|error| format!("invalid artifact_hex: {error}"))
}

/// Builds a protocol refusal without conflating it with a harness failure.
fn refusal(reason: &str) -> Value {
    json!({"answer": "refusal", "reason": reason})
}

/// Resolves every supplied binding independently against the same responder.
///
/// Categories default to supported; responder capability (including overrides)
/// takes precedence over the corpus-level `categories_supported` capability.
/// Framing failures become malformed-request refusals, not missing evidence.
fn resolve(case: &Value, context: &Value) -> Result<Value, String> {
    let mut responder = member(context, "responder")?
        .as_object()
        .ok_or_else(|| "responder must be an object".to_owned())?
        .clone();
    if let Some(overrides) = case.get("responder_overrides") {
        let overrides = overrides
            .as_object()
            .ok_or_else(|| "responder_overrides must be an object".to_owned())?;
        responder.extend(overrides.clone());
    }
    let responder = Value::Object(responder);
    let categories_supported = match responder
        .get("categories_supported")
        .or_else(|| context.get("categories_supported"))
    {
        Some(value) => value
            .as_bool()
            .ok_or("categories_supported must be boolean")?,
        None => true,
    };
    let mut results = Vec::new();
    if let Some(source) = case.get("request_json") {
        let source = source.as_str().ok_or("request_json must be text")?;
        results.push(resolve_decoded_request(
            protocol::decode_json(source.as_bytes()),
            &responder,
            categories_supported,
        )?);
    }
    if let Some(source) = case.get("request_cbor_hex") {
        let source = source.as_str().ok_or("request_cbor_hex must be text")?;
        let document = hex::decode(source)
            .map_err(|error| error.to_string())
            .and_then(|bytes| protocol::decode_cbor(&bytes));
        results.push(resolve_decoded_request(
            document,
            &responder,
            categories_supported,
        )?);
    }
    let result = results
        .first()
        .ok_or("missing request_json or request_cbor_hex")?;
    if results.iter().any(|other| other != result) {
        return Err("JSON and CBOR resolution results disagree".to_owned());
    }
    Ok(result.clone())
}

/// Validates native request syntax before projecting understood resolution fields.
///
/// Unknown request and coverage extensions remain opaque, including native CBOR
/// values that cannot be represented in JSON.
fn resolve_decoded_request(
    document: Result<crate::wire::Value, String>,
    responder: &Value,
    categories_supported: bool,
) -> Result<Value, String> {
    let request = match document {
        Ok(request) => request,
        Err(_) => return Ok(refusal("request_malformed")),
    };
    let validation = protocol::validate_request(&request, categories_supported);
    if validation.get("well_formed").and_then(Value::as_bool) != Some(true) {
        return Ok(refusal(text(&validation, "reason")?));
    }
    let subject = request
        .get("subject")
        .ok_or("missing validated subject")?
        .to_json()?;
    let coverage = request
        .get("coverage")
        .ok_or("missing validated coverage")?
        .project_json(&["expected_pin", "min_freshness"])?;
    let mut projected = json!({"subject": subject, "coverage": coverage});
    if let Some(derivation) = request.get("derivation") {
        projected["derivation"] = derivation.to_json()?;
    }
    let request = projected;
    let (form, content) = subject_form(member(&request, "subject")?)?;
    if responder
        .get("uniform_policy_declined")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Ok(refusal("policy_declined"));
    }
    if let Some(derivation) = request.get("derivation").and_then(Value::as_str) {
        let supported = member(responder, "supported_derivations")?;
        let Some(forms) = supported.get(derivation) else {
            return Ok(refusal("derivation_unsupported"));
        };
        if !string_array_contains(forms, form)? {
            return Ok(refusal("no_such_subject"));
        }
    }
    let held = match form {
        "record" => string_array_contains(member(responder, "records")?, value_text(content)?)?,
        "correlation" | "exchange" => {
            let index = member(
                responder,
                if form == "correlation" {
                    "correlations"
                } else {
                    "exchange_citations"
                },
            )?;
            match index.get(value_text(content)?) {
                Some(records) => !records
                    .as_array()
                    .ok_or_else(|| "subject index entries must be arrays".to_owned())?
                    .is_empty(),
                None => false,
            }
        }
        "range" => {
            if responder
                .get("positional_ordering")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Ok(refusal("coverage_unsatisfiable"));
            }
            true
        }
        "full_history" | "checkpoints" => true,
        _ => return Err(format!("unsupported subject: {form}")),
    };
    if !held {
        return Ok(refusal("no_such_subject"));
    }
    let coverage = member(&request, "coverage")?;
    let anchors = member(responder, "anchors")?
        .as_array()
        .ok_or_else(|| "anchors must be an array".to_owned())?;
    for anchor in anchors {
        if anchor_satisfies(coverage, anchor)? {
            if form == "range" {
                let end = content
                    .get(1)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "range end must be unsigned".to_owned())?;
                let size = member(anchor, "size")?
                    .as_u64()
                    .ok_or_else(|| "anchor size must be unsigned".to_owned())?;
                if end >= size {
                    continue;
                }
            }
            return Ok(json!({"answer": "artifact"}));
        }
    }
    // An exchange half sealed by the requester can itself be the coverage pin;
    // it need not also appear in the responder's local checkpoint list.
    if form == "exchange" && coverage.get("expected_pin") == Some(content) {
        return Ok(json!({"answer": "artifact"}));
    }
    if responder
        .get("issues_new_commitments")
        .and_then(Value::as_bool)
        == Some(true)
        && coverage.get("min_freshness").is_some()
    {
        return Err("new commitment issuance requires a concrete qualifying anchor".to_owned());
    }
    Ok(refusal("coverage_unsatisfiable"))
}

/// Obtains subject text after structural validation, without panic assumptions.
fn value_text(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| "subject content must be text".to_owned())
}

/// Checks exact membership in a declared responder string array.
fn string_array_contains(array: &Value, needle: &str) -> Result<bool, String> {
    let entries = array
        .as_array()
        .ok_or_else(|| "holdings must be an array".to_owned())?;
    if entries.iter().any(|entry| !entry.is_string()) {
        return Err("holdings entries must be text".to_owned());
    }
    Ok(entries.iter().any(|entry| entry.as_str() == Some(needle)))
}

/// Checks a concrete anchor against an exact pin or a size/time freshness floor.
fn anchor_satisfies(coverage: &Value, anchor: &Value) -> Result<bool, String> {
    if let Some(pin) = coverage.get("expected_pin") {
        return Ok(anchor.get("digest") == Some(pin));
    }
    let floor = member(coverage, "min_freshness")?;
    if let Some(size) = floor.as_u64() {
        let anchor_size = member(anchor, "size")?
            .as_u64()
            .ok_or_else(|| "anchor size must be unsigned".to_owned())?;
        return Ok(anchor_size >= size);
    }
    let floor = value_text(floor)?
        .parse::<Timestamp>()
        .map_err(|error| format!("invalid freshness timestamp: {error}"))?;
    let issued = text(anchor, "issued_at")?
        .parse::<Timestamp>()
        .map_err(|error| format!("invalid anchor timestamp: {error}"))?;
    Ok(issued >= floor)
}
