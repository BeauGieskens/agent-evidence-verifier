//! Lossless JSON and CBOR decoding, independent of protocol field validation.

use std::{fmt, io::Cursor};

use ciborium::value::Value as CborValue;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Number, value::RawValue};

/// A document value retaining native CBOR types and arbitrary-precision JSON numbers.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A null value.
    Null,
    /// A boolean value.
    Bool(bool),
    /// A JSON number, retaining its arbitrary-precision representation.
    Number(Number),
    /// A native CBOR integer, including values outside the signed 64-bit range.
    Integer(i128),
    /// A native CBOR float, including infinities, NaNs, and signed zero.
    Float(f64),
    /// A Unicode text string.
    Text(String),
    /// A native CBOR byte string.
    Bytes(Vec<u8>),
    /// An ordered sequence of values.
    Array(Vec<Value>),
    /// Map entries retaining native keys and source order.
    Map(Vec<(Value, Value)>),
    /// A CBOR semantic tag and its enclosed value.
    Tag(u64, Box<Value>),
}

impl Value {
    /// Looks up a text key without interpreting tags or coercing other key types.
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_map()?
            .iter()
            .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
    }

    /// Returns the contents of a text string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the contents of a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns an unsigned 64-bit integer without coercing floating-point values.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.as_u64(),
            Self::Integer(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    /// Reports whether this value is a text string.
    pub fn is_string(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Reports whether this value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns the elements of an array.
    pub fn as_array(&self) -> Option<&Vec<Self>> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Returns map entries without restricting their key types.
    pub fn as_map(&self) -> Option<&[(Self, Self)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// Projects understood members without inspecting or converting extension values.
    ///
    /// Unknown keys, including non-text CBOR keys, remain opaque. Duplicate
    /// understood members are ambiguous and cannot form a projected object.
    pub fn project_json(&self, members: &[&str]) -> Result<serde_json::Value, String> {
        let entries = self.as_map().ok_or("expected a map")?;
        let mut object = serde_json::Map::new();
        for (key, value) in entries {
            let Some(key) = key.as_str().filter(|key| members.contains(key)) else {
                continue;
            };
            if object.contains_key(key) {
                return Err(format!("duplicate understood member: {key}"));
            }
            object.insert(key.to_owned(), value.to_json()?);
        }
        Ok(serde_json::Value::Object(object))
    }

    /// Converts JSON-compatible data for harness consumers without special markers.
    ///
    /// Rejects byte strings, tags, non-finite floats, non-text keys, and duplicate
    /// object keys rather than silently discarding their native semantics.
    pub fn to_json(&self) -> Result<serde_json::Value, String> {
        match self {
            Self::Null => Ok(serde_json::Value::Null),
            Self::Bool(value) => Ok(serde_json::Value::Bool(*value)),
            Self::Number(value) => Ok(serde_json::Value::Number(value.clone())),
            Self::Integer(value) => value
                .to_string()
                .parse::<Number>()
                .map(serde_json::Value::Number)
                .map_err(|error| format!("integer cannot be represented in JSON: {error}")),
            Self::Float(value) => Number::from_f64(*value)
                .map(serde_json::Value::Number)
                .ok_or_else(|| "non-finite float cannot be represented in JSON".to_owned()),
            Self::Text(value) => Ok(serde_json::Value::String(value.clone())),
            Self::Bytes(_) => {
                Err("byte string cannot be represented losslessly in JSON".to_owned())
            }
            Self::Tag(_, _) => Err("CBOR tag cannot be represented losslessly in JSON".to_owned()),
            Self::Array(values) => values
                .iter()
                .map(Self::to_json)
                .collect::<Result<Vec<_>, _>>()
                .map(serde_json::Value::Array),
            Self::Map(entries) => {
                let mut object = serde_json::Map::new();
                for (key, value) in entries {
                    let Self::Text(key) = key else {
                        return Err("non-text map key cannot be represented in JSON".to_owned());
                    };
                    if object.contains_key(key) {
                        return Err(format!("duplicate JSON object key: {key:?}"));
                    }
                    object.insert(key.clone(), value.to_json()?);
                }
                Ok(serde_json::Value::Object(object))
            }
        }
    }
}

/// Decodes one complete JSON document, falling back to one complete CBOR document.
pub fn decode_document(bytes: &[u8]) -> Result<Value, String> {
    match decode_json(bytes) {
        Ok(value) => Ok(value),
        Err(json_error) => decode_cbor(bytes)
            .map_err(|cbor_error| format!("invalid JSON ({json_error}) or CBOR ({cbor_error})")),
    }
}

/// Decodes exactly one JSON document without reserving keys or limiting numbers.
///
/// Only JSON whitespace may follow the document. Object members are preserved,
/// including duplicates; field consumers decide whether a repeated name is
/// ambiguous. Unknown extension objects need not satisfy JCS's unique-key rule.
pub fn decode_json(bytes: &[u8]) -> Result<Value, String> {
    let raw: &RawValue = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    json_value(raw)
}

/// Decodes exactly one CBOR document, preserving native types and rejecting duplicates.
///
/// Map keys may have any native type. Duplicate comparison ignores map entry
/// ordering and treats NaNs as equal, while retaining integer/float distinctions.
pub fn decode_cbor(bytes: &[u8]) -> Result<Value, String> {
    let mut cursor = Cursor::new(bytes);
    let value: CborValue = ciborium::from_reader(&mut cursor).map_err(|error| error.to_string())?;
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing CBOR data".to_owned());
    }
    cbor_value(value)
}

/// Borrowed object entries keep duplicate keys visible until explicitly checked.
struct RawObject<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for RawObject<'de> {
    /// Deserializes an object without passing through serde_json's object map.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RawObjectVisitor)
    }
}

/// Collects raw object members without imposing a schema on extension objects.
struct RawObjectVisitor;

impl<'de> Visitor<'de> for RawObjectVisitor {
    type Value = RawObject<'de>;

    /// Describes the expected JSON object for deserialization errors.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    /// Retains every decoded member so known-field checks cannot lose duplicates.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<String, &'de RawValue>()? {
            entries.push(entry);
        }
        Ok(RawObject(entries))
    }
}

/// Expands validated raw JSON recursively without losing number tokens or keys.
fn json_value(raw: &RawValue) -> Result<Value, String> {
    let source = raw.get();
    match source.as_bytes().first() {
        Some(b'n') => Ok(Value::Null),
        Some(b't') => Ok(Value::Bool(true)),
        Some(b'f') => Ok(Value::Bool(false)),
        Some(b'"') => serde_json::from_str(source)
            .map(Value::Text)
            .map_err(|error| error.to_string()),
        Some(b'[') => {
            let values: Vec<&RawValue> =
                serde_json::from_str(source).map_err(|error| error.to_string())?;
            values
                .into_iter()
                .map(json_value)
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        Some(b'{') => {
            let RawObject(entries) =
                serde_json::from_str(source).map_err(|error| error.to_string())?;
            entries
                .into_iter()
                .map(|(key, value)| Ok((Value::Text(key), json_value(value)?)))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Map)
        }
        _ => source
            .parse::<Number>()
            .map(Value::Number)
            .map_err(|error| error.to_string()),
    }
}

/// Converts CBOR recursively, checking maps before exposing their entries.
fn cbor_value(value: CborValue) -> Result<Value, String> {
    match value {
        CborValue::Null => Ok(Value::Null),
        CborValue::Bool(value) => Ok(Value::Bool(value)),
        CborValue::Integer(value) => Ok(Value::Integer(value.into())),
        CborValue::Float(value) => Ok(Value::Float(value)),
        CborValue::Text(value) => Ok(Value::Text(value)),
        CborValue::Bytes(value) => Ok(Value::Bytes(value)),
        CborValue::Tag(tag, value) => Ok(Value::Tag(tag, Box::new(cbor_value(*value)?))),
        CborValue::Array(values) => values
            .into_iter()
            .map(cbor_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        CborValue::Map(entries) => {
            let mut values: Vec<(Value, Value)> = Vec::new();
            for (key, value) in entries {
                let key = cbor_value(key)?;
                if values
                    .iter()
                    .any(|(previous, _)| keys_equal(previous, &key))
                {
                    return Err("duplicate CBOR map key".to_owned());
                }
                values.push((key, cbor_value(value)?));
            }
            Ok(Value::Map(values))
        }
        _ => Err("unsupported CBOR value".to_owned()),
    }
}

/// Compares native CBOR keys, including compound keys and reflexive NaN equality.
fn keys_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Float(left), Value::Float(right)) => {
            left == right || (left.is_nan() && right.is_nan())
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| keys_equal(left, right))
        }
        (Value::Map(left), Value::Map(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right.iter().any(|(other_key, other_value)| {
                        keys_equal(key, other_key) && keys_equal(value, other_value)
                    })
                })
        }
        (Value::Tag(left_tag, left), Value::Tag(right_tag, right)) => {
            left_tag == right_tag && keys_equal(left, right)
        }
        _ => left == right,
    }
}
