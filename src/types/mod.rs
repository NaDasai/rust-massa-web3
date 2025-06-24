pub mod event;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadStorageKey {
    pub smart_contract_address: String,
    pub key: String,
}

// --- ArgTypes / ArrayTypes (Optional, depends on usage) ---
// Rust's type system often makes these less necessary than in JS.
// If you need dynamic dispatch based on type at runtime, you might define them.
// For now, we'll rely on generics and specific methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayType {
    String,
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
    F32,
    F64,
    // Note: Serializable objects need special handling, not just a simple type enum
}

#[derive(Debug, Clone)]
pub enum ChainId {
    MAINNET = 77658377,
    BUILDNET = 77658366,
}

impl ChainId {
    pub fn to_u64(&self) -> u64 {
        match self {
            ChainId::MAINNET => 77658377,
            ChainId::BUILDNET => 77658366,
        }
    }
}
