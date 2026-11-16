//! Runs existing evidence-request corpora, never synthesizing expected answers.

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

use agent_evidence_verifier::{evaluate_case, protocol::decode_document};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::Error;

/// Runs a corpus file or a directory named by its pinned manifest.
///
/// Every case emits one JSON line. All positive assertions and forbidden-state
/// assertions are checked; unknown assertion types fail instead of being skipped.
pub fn run(path: &Path, selected: Option<&str>) -> Result<bool, Error> {
    let mut corpora = Vec::new();
    if path.is_dir() {
        let manifest = read(&path.join("manifest.json"))?;
        let files = manifest
            .get("files")
            .and_then(Value::as_array)
            .ok_or("manifest files must be an array")?;
        for entry in files {
            let name = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or("manifest entry missing path")?;
            let relative = Path::new(name);
            if relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(format!("unsafe manifest path: {name}").into());
            }
            let file = path.join(relative);
            let bytes = fs::read(&file)?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if entry.get("sha256").and_then(Value::as_str) != Some(actual.as_str()) {
                return Err(format!("manifest hash mismatch: {}", file.display()).into());
            }
            let document = decode_document(&bytes)?.to_json()?;
            if let Some(cases) = document.get("cases").and_then(Value::as_array) {
                if entry.get("count").and_then(Value::as_u64) != Some(cases.len() as u64)
                    || document.get("count").and_then(Value::as_u64) != Some(cases.len() as u64)
                {
                    return Err(format!("case count mismatch: {name}").into());
                }
                corpora.push((file, document));
            } else if name != "registry.json" && name != "refusal-imported.json" {
                return Err(format!("manifest member has no supported corpus: {name}").into());
            }
        }
    } else {
        corpora.push((path.to_owned(), read(path)?));
    }
    let mut passed = 0;
    let mut failed = 0;
    let mut ids = BTreeSet::new();
    for (path, document) in corpora {
        let cases = document
            .get("cases")
            .and_then(Value::as_array)
            .ok_or("file has no cases array")?;
        for case in cases {
            let id = case
                .get("id")
                .and_then(Value::as_str)
                .ok_or("case missing id")?;
            if !ids.insert(id.to_owned()) {
                return Err(format!("duplicate case id: {id}").into());
            }
            if selected.is_some_and(|wanted| wanted != id) {
                continue;
            }
            let expected = case.get("expect").ok_or("case missing expect")?;
            let mut input = case.clone();
            if let Some(file) = case.get("file").and_then(Value::as_str) {
                let relative = Path::new(file);
                if relative.components().count() != 1
                    || !matches!(relative.components().next(), Some(Component::Normal(_)))
                {
                    return Err(format!("unsafe fixture path: {file}").into());
                }
                let imported = read(
                    &path
                        .parent()
                        .ok_or("corpus has no parent directory")?
                        .join(relative),
                )?;
                input
                    .as_object_mut()
                    .ok_or("case must be an object")?
                    .insert("refusal".into(), imported);
            }
            let (actual, errors) = match evaluate_case(&input, &document) {
                Ok(actual) => {
                    let mut errors = Vec::new();
                    compare(expected, &actual, "", &mut errors);
                    (actual, errors)
                }
                Err(error) => (Value::Null, vec![error.to_string()]),
            };
            let pass = errors.is_empty();
            if pass {
                passed += 1;
            } else {
                failed += 1;
            }
            println!(
                "{}",
                json!({"file":path,"id":id,"pass":pass,"actual":actual,"errors":errors})
            );
        }
    }
    if passed + failed == 0 {
        return Err("no matching vector cases".into());
    }
    eprintln!("{passed} passed; {failed} failed");
    Ok(failed == 0)
}

/// Reads strict JSON/CBOR without allowing duplicate members or trailing data.
fn read(path: &Path) -> Result<Value, Error> {
    decode_document(&fs::read(path)?)
        .and_then(|document| document.to_json())
        .map_err(|error| format!("{}: {error}", path.display()).into())
}

/// Checks all declared fields, with explicit support for forbidden output states.
fn compare(expected: &Value, actual: &Value, path: &str, errors: &mut Vec<String>) {
    if let Some(object) = expected.as_object() {
        for (key, value) in object {
            let field = format!("{path}/{key}");
            let forbidden_field = match key.as_str() {
                "must_not_record_as" => Some("state"),
                "must_not_classify_as" => Some("classified_as"),
                "must_not_show_as" => Some("shown_as"),
                "not_reason" => Some("reason"),
                _ => None,
            };
            if let Some(output_field) = forbidden_field {
                match (value.as_array(), actual.get(output_field)) {
                    (Some(forbidden), Some(output)) => {
                        if forbidden.contains(output) {
                            errors.push(format!("{field}: forbidden output {output}"));
                        }
                    }
                    _ => errors.push(format!(
                        "{field}: missing output or malformed exclusion assertion"
                    )),
                }
            } else if let Some(actual) = actual.get(key) {
                compare(value, actual, &field, errors);
            } else {
                errors.push(format!("{field}: missing result; expected {value}"));
            }
        }
    } else if expected != actual {
        errors.push(format!("{path}: expected {expected}, got {actual}"));
    }
}
