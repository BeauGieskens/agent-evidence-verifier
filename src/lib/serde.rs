use serde::{Deserialize, Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

use crate::Digest;

/// Hex wire encoding for digest bytes, independent of hash algorithm or length.
pub mod digest {
    use super::*;

    /// Applies the digest codec to container elements through `serde_as`.
    pub struct Codec;

    /// Encodes digest bytes as lowercase hex.
    pub fn serialize<S: Serializer>(digest: &Digest, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(digest))
    }

    /// Decodes hex text of either case into digest bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Digest, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex).map_err(serde::de::Error::custom)?;
        Ok(bytes.into())
    }

    impl SerializeAs<Digest> for Codec {
        fn serialize_as<S: Serializer>(source: &Digest, serializer: S) -> Result<S::Ok, S::Error> {
            serialize(source, serializer)
        }
    }

    impl<'de> DeserializeAs<'de, Digest> for Codec {
        fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Digest, D::Error> {
            deserialize(deserializer)
        }
    }
}
