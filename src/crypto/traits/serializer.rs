use anyhow::Result;

pub trait Serializer: Send + Sync {
    // Takes versioned bytes
    fn serialize(&self, data: &[u8]) -> String;
    // Returns versioned bytes
    fn deserialize(&self, s: &str) -> Result<Vec<u8>>;
}
