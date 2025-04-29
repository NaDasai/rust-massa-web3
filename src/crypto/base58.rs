use anyhow::{Context, Result};

use super::traits::serializer::Serializer;

// Base58 Serializer
#[derive(Debug, Clone, Copy, Default)]
pub struct Base58Serializer;


impl Serializer for Base58Serializer {
    fn serialize(&self, data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }

    fn deserialize(&self, s: &str) -> Result<Vec<u8>> {
        bs58::decode(s)
            .into_vec()
            .with_context(|| format!("Failed to decode Base58 string: '{}'", s))
    }
}


