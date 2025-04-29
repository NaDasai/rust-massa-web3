use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature as DalekSignature,
    Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
use rand::rngs::OsRng; // Cryptographically secure random number generator
use std::{env, fmt, str::FromStr};

use crate::crypto::{base58::Base58Serializer, traits::serializer::Serializer};

pub const PRIVATE_KEY_PREFIX: &str = "S";
pub const PUBLIC_KEY_PREFIX: &str = "P";

pub fn is_private_key(key: &str) -> bool {
    key.starts_with(PRIVATE_KEY_PREFIX)
}

pub fn is_public_key(key: &str) -> bool {
    key.starts_with(PUBLIC_KEY_PREFIX)
}

// --- Version Enum ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)] // Explicitly represent as u8
pub enum Version {
    V0 = 0,
    V1 = 1,
}

impl Version {
    // Convert from a byte
    fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Version::V0),
            1 => Ok(Version::V1),
            _ => bail!("Unsupported version byte: {}", byte),
        }
    }
}

// --- Crypto Traits (Interfaces) ---
pub trait Hasher: Send + Sync {
    // Add Send + Sync for potential multithreading
    fn hash(&self, data: &[u8]) -> Vec<u8>; // Blake3 default is 32 bytes
    // Optional: Provide a method for fixed-size output if needed
    // fn hash_fixed(&self, data: &[u8]) -> [u8; 32];
}

pub trait Signer: Send + Sync {
    // Returns raw private key bytes (without version)
    fn generate_private_key(&self) -> Vec<u8>;
    // Takes raw private key bytes, returns raw public key bytes
    fn get_public_key(&self, private_key_bytes: &[u8]) -> Result<Vec<u8>>;
    // Takes raw private key bytes and message hash, returns raw signature bytes
    fn sign(&self, private_key_bytes: &[u8], message_hash: &[u8]) -> Result<Vec<u8>>;
    // Takes raw public key bytes, message hash, and raw signature bytes
    fn verify(
        &self,
        public_key_bytes: &[u8],
        message_hash: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool>;
}


pub trait Versioner: Send + Sync {
    // Attaches version prefix to raw data
    fn attach(&self, version: Version, raw_data: &[u8]) -> Vec<u8>;
    // Extracts version and raw data from versioned data
    fn extract<'a>(&self, versioned_data: &'a [u8]) -> Result<(Version, &'a [u8])>;
}

// --- Concrete Implementations ---

// Blake3 Hasher
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Hasher;
impl Hasher for Blake3Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
    // fn hash_fixed(&self, data: &[u8]) -> [u8; 32] {
    //     *blake3::hash(data).as_bytes()
    // }
}

// Ed25519 Signer
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Signer;
impl Signer for Ed25519Signer {
    fn generate_private_key(&self) -> Vec<u8> {
        // TODO: Replace with secure random number generation
        let random_bytes = rand::random::<[u8; 32]>();
        random_bytes.to_vec() // Returns the 32-byte secret scalar
    }

    fn get_public_key(&self, private_key_bytes: &[u8]) -> Result<Vec<u8>> {
        println!("private_key_bytes: {:?}", private_key_bytes);

        let secret_key: &[u8; 32] = private_key_bytes.split_at(32).0.try_into().expect("Invalid private key length for Ed25519");

        println!("secret_key: {:?}", secret_key);

        // Convert the private key bytes to a SigningKey
        let signing_key = SigningKey::from_bytes(secret_key);
        Ok(signing_key.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, private_key_bytes: &[u8], message_hash: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(
            private_key_bytes
                .try_into()
                .context("Invalid private key length for Ed25519")?,
        );
        // ed25519 signs the message itself, not the pre-hash in standard implementations
        // However, the JS code passes the hash. To match that *exact* behavior (which is non-standard for Ed25519):
        // We will sign the hash as if it were the message. Be aware this differs from typical Ed25519 usage.
        let signature = signing_key.sign(message_hash);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(
        &self,
        public_key_bytes: &[u8],
        message_hash: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(
            public_key_bytes
                .try_into()
                .context("Invalid public key length for Ed25519")?,
        )?;
        let signature = DalekSignature::from_bytes(
            signature_bytes
                .try_into()
                .context("Invalid signature length for Ed25519")?,
        );
        // Verify the hash as if it were the message, matching the non-standard signing behavior above.
        Ok(verifying_key.verify(message_hash, &signature).is_ok())
    }
}


// Simple Prefix Versioner (assumes single byte version)
#[derive(Debug, Clone, Copy, Default)]
pub struct SimplePrefixVersioner;
impl Versioner for SimplePrefixVersioner {
    fn attach(&self, version: Version, raw_data: &[u8]) -> Vec<u8> {
        let mut versioned_data = Vec::with_capacity(1 + raw_data.len());
        versioned_data.push(version as u8);
        versioned_data.extend_from_slice(raw_data);
        versioned_data
    }

    fn extract<'a>(&self, versioned_data: &'a [u8]) -> Result<(Version, &'a [u8])> {
        if versioned_data.is_empty() {
            bail!("Cannot extract version from empty data");
        }
        let version_byte = versioned_data[0];
        let version = Version::from_u8(version_byte)?;
        let raw_data = &versioned_data[1..];
        Ok((version, raw_data))
    }
}

// --- Signature Struct ---
// A simple wrapper around the versioned signature bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    versioned_bytes: Vec<u8>,
    // Caching extracted info might be useful
    // version: Version,
    // raw_bytes: Vec<u8>,
}

impl Signature {
    /// Creates a Signature from versioned bytes. Use this internally.
    pub fn from_bytes(versioned_bytes: Vec<u8>) -> Result<Self> {
        // Basic validation: Ensure version can be extracted
        let versioner = SimplePrefixVersioner; // Assuming V0 uses this
        versioner.extract(&versioned_bytes)?;
        Ok(Self { versioned_bytes })
    }

    /// Returns the raw signature bytes (without version prefix).
    pub fn to_raw_bytes(&self) -> Result<Vec<u8>> {
        let versioner = SimplePrefixVersioner; // Assuming V0 uses this
        let (_, raw_data) = versioner.extract(&self.versioned_bytes)?;
        Ok(raw_data.to_vec())
    }

    /// Returns the full versioned signature bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.versioned_bytes.clone()
    }

    /// Creates a Signature from a Base58 encoded string (assuming some prefix if needed).
    /// This example assumes no prefix for signatures, adjust if necessary.
    pub fn from_string(s: &str) -> Result<Self> {
        let serializer = Base58Serializer; // Assuming V0 uses this
        let versioned_bytes = serializer.deserialize(s)?;
        Self::from_bytes(versioned_bytes)
    }

    /// Serializes the signature to a Base58 string (assuming no prefix).
    pub fn to_string(&self) -> String {
        let serializer = Base58Serializer; // Assuming V0 uses this
        serializer.serialize(&self.versioned_bytes)
    }
}

// --- Address Struct (Placeholder) ---
// Needs definition based on how addresses are derived (e.g., hash of public key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    // Example: Store as bytes or string
    value: String, // Or Vec<u8>
}

impl Address {
    // This needs the actual address derivation logic
    pub fn from_public_key<H, S, Ser, Ver>(public_key: &PublicKey<H, S, Ser, Ver>) -> Result<Self>
    where
        H: Hasher + 'static,
        S: Signer + 'static,
        Ser: Serializer + 'static,
        Ver: Versioner + 'static,
    {
        // Example: Hash the raw public key bytes
        let (_, raw_pk_bytes) = public_key.versioner.extract(&public_key.bytes)?;
        let hash = public_key.hasher.hash(raw_pk_bytes);

        // Example: Encode the hash (e.g., Base58 with a prefix)
        // This part is highly specific to the blockchain's address format
        let addr_string = format!("AU{}", bs58::encode(hash).into_string()); // Placeholder format

        Ok(Address { value: addr_string })
    }

    pub fn to_string(&self) -> String {
        self.value.clone()
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Add validation based on expected address format
        if s.starts_with("addr_") {
            // Placeholder validation
            Ok(Address {
                value: s.to_string(),
            })
        } else {
            bail!("Invalid address format: {}", s);
        }
    }
}

// --- PrivateKey Struct ---
#[derive(Clone)] // Clone might be expensive if Box<dyn Trait> is large, but needed for easy copying
pub struct PrivateKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    bytes: Vec<u8>, // Versioned bytes
    hasher: H,
    signer: S,
    serializer: Ser,
    versioner: Ver,
    version: Version, // Cache the version
}

// Manual Debug implementation because traits might not implement Debug
impl<H, S, Ser, Ver> fmt::Debug for PrivateKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("version", &self.version)
            .field("bytes (len)", &self.bytes.len())
            // Don't print actual bytes for security
            .finish()
    }
}

impl PrivateKey<Blake3Hasher, Ed25519Signer, Base58Serializer, SimplePrefixVersioner> {
    /// Initializes a V0 private key object.
    fn init_v0() -> Self {
        let version = Version::V0;
        Self {
            bytes: Vec::new(), // Placeholder, will be set by generate/from_*
            hasher: Blake3Hasher::default(),
            signer: Ed25519Signer::default(),
            serializer: Base58Serializer::default(),
            versioner: SimplePrefixVersioner::default(),
            version,
        }
    }
}

// Generic implementation block
impl<H, S, Ser, Ver> PrivateKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    // Helper to create instance based on version - currently only supports V0
    fn init_from_version(version: Version) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        match version {
            Version::V0 => Ok(Self {
                bytes: Vec::new(),
                hasher: H::default(),
                signer: S::default(),
                serializer: Ser::default(),
                versioner: Ver::default(),
                version,
            }),
            Version::V1 => Ok(Self {
                bytes: Vec::new(),
                hasher: H::default(),
                signer: S::default(),
                serializer: Ser::default(),
                versioner: Ver::default(),
                version,
            }),
            _ => bail!("Unsupported private key version: {:?}", version),
        }
    }

    /// Creates a PrivateKey from a Base58 encoded string with prefix.
    pub fn from_string(s: &str) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        // 1. Determine version (simplified: assume V0 for now, JS version also hardcodes V0)
        // let version = get_version(s)?; // get_version needs robust implementation
        let version = Version::V0; // Hardcoded assumption matching JS getVersion

        // 2. Initialize components based on version
        let mut key = Self::init_from_version(version)?;

        dbg!(&key);

        // 3. Check and strip prefix
        let data_part = s.strip_prefix(PRIVATE_KEY_PREFIX).ok_or_else(|| {
            anyhow!(
                "Invalid private key prefix: expected '{}'",
                PRIVATE_KEY_PREFIX
            )
        })?;

        // 4. Deserialize
        key.bytes = key
            .serializer
            .deserialize(data_part)
            .context("Failed to deserialize private key data")?;

        // 5. Verify extracted version matches expected version (optional but good practice)
        let (extracted_version, _) = key
            .versioner
            .extract(&key.bytes)
            .context("Failed to extract version from deserialized private key bytes")?;
        if extracted_version != key.version {
            bail!(
                "Version mismatch: Expected {:?} based on format, but found {:?} in data",
                key.version,
                extracted_version
            );
        }

        Ok(key)
    }

    /// Creates a PrivateKey from versioned bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        // 1. Determine version from bytes
        // For now, assume SimplePrefixVersioner is always used for extraction if not known otherwise
        let temp_versioner = SimplePrefixVersioner; // Use a temporary versioner just to extract the version byte
        let (version, _) = temp_versioner
            .extract(&bytes)
            .context("Failed to extract version from private key bytes")?;

        // 2. Initialize components based on version
        let mut key = Self::init_from_version(version)?;
        key.bytes = bytes; // Store the provided bytes

        Ok(key)
    }

    /// Creates a PrivateKey from an environment variable.
    pub fn from_env(var_name: &str) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        let key_str = env::var(var_name)
            .with_context(|| format!("Missing environment variable '{}'", var_name))?;
        Self::from_string(&key_str).with_context(|| {
            format!(
                "Failed to parse private key from environment variable '{}'",
                var_name
            )
        })
    }

    /// Generates a new random PrivateKey for the given version.
    pub fn generate(version: Version) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        let mut key = Self::init_from_version(version)?;
        let raw_bytes = key.signer.generate_private_key();
        key.bytes = key.versioner.attach(key.version, &raw_bytes);
        Ok(key)
    }

    /// Returns the versioned private key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Serializes the private key to a string (Base58 with prefix).
    pub fn to_string(&self) -> String {
        format!(
            "{}{}",
            PRIVATE_KEY_PREFIX,
            self.serializer.serialize(&self.bytes)
        )
    }

    /// Derives the corresponding PublicKey.
    pub fn get_public_key(&self) -> Result<PublicKey<H, S, Ser, Ver>>
    where
        H: Clone + Default,
        S: Clone + Default,
        Ser: Clone + Default,
        Ver: Clone + Default, // Need Clone and Default for components
    {
        PublicKey::from_private_key(self)
    }

    /// Signs a message (hashes first, then signs the hash).
    /// Note: This matches the JS behavior but is non-standard for Ed25519.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let message_hash = self.hasher.hash(message);
        let (version, raw_private_key) = self.versioner.extract(&self.bytes)?;
        let raw_signature = self.signer.sign(raw_private_key, &message_hash)?;
        let versioned_signature = self.versioner.attach(version, &raw_signature);
        Signature::from_bytes(versioned_signature) // Wrap in Signature struct
    }
}

// --- PublicKey Struct ---
#[derive(Clone)] // Clone might be expensive if Box<dyn Trait> is large
pub struct PublicKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    bytes: Vec<u8>, // Versioned bytes
    hasher: H,
    signer: S,
    serializer: Ser,
    versioner: Ver,
    version: Version,
}

// Manual Debug implementation
impl<H, S, Ser, Ver> fmt::Debug for PublicKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("version", &self.version)
            .field("bytes (len)", &self.bytes.len())
            .finish()
    }
}

// Generic implementation block
impl<H, S, Ser, Ver> PublicKey<H, S, Ser, Ver>
where
    H: Hasher + 'static,
    S: Signer + 'static,
    Ser: Serializer + 'static,
    Ver: Versioner + 'static,
{
    // Helper to create instance based on version - currently only supports V0
    fn init_from_version(version: Version) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        match version {
            Version::V0 => Ok(Self {
                bytes: Vec::new(),
                hasher: H::default(),
                signer: S::default(),
                serializer: Ser::default(),
                versioner: Ver::default(),
                version,
            }),
            Version::V1 => Ok(Self {
                bytes: Vec::new(),
                hasher: H::default(),
                signer: S::default(),
                serializer: Ser::default(),
                versioner: Ver::default(),
                version,
            }),
            _ => bail!("Unsupported public key version: {:?}", version),
        }
    }

    /// Creates a PublicKey from a Base58 encoded string with prefix.
    pub fn from_string(s: &str) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        let version = Version::V0; // Hardcoded assumption matching JS getVersion
        let mut key = Self::init_from_version(version)?;

        let data_part = s.strip_prefix(PUBLIC_KEY_PREFIX).ok_or_else(|| {
            anyhow!(
                "Invalid public key prefix: expected '{}'",
                PUBLIC_KEY_PREFIX
            )
        })?;

        key.bytes = key
            .serializer
            .deserialize(data_part)
            .context("Failed to deserialize public key data")?;

        let (extracted_version, _) = key
            .versioner
            .extract(&key.bytes)
            .context("Failed to extract version from deserialized public key bytes")?;
        if extracted_version != key.version {
            bail!(
                "Version mismatch: Expected {:?} based on format, but found {:?} in data",
                key.version,
                extracted_version
            );
        }

        Ok(key)
    }

    /// Creates a PublicKey from versioned bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self>
    where
        // Specify bounds here if needed for default() or other trait methods
        H: Default,
        S: Default,
        Ser: Default,
        Ver: Default,
    {
        let temp_versioner = SimplePrefixVersioner;
        let (version, _) = temp_versioner
            .extract(&bytes)
            .context("Failed to extract version from public key bytes")?;

        let mut key = Self::init_from_version(version)?;
        key.bytes = bytes;

        Ok(key)
    }

    /// Derives a PublicKey from a PrivateKey.
    pub fn from_private_key(private_key: &PrivateKey<H, S, Ser, Ver>) -> Result<Self>
    where
        H: Clone + Default, // Need Clone and Default to create new PublicKey instance
        S: Clone + Default,
        Ser: Clone + Default,
        Ver: Clone + Default,
    {
        // Ensure versions match or handle compatibility if needed
        let version = private_key.version;
        let mut public_key = Self::init_from_version(version)?;

        // Use the private key's components
        public_key.hasher = private_key.hasher.clone();
        public_key.signer = private_key.signer.clone();
        public_key.serializer = private_key.serializer.clone();
        public_key.versioner = private_key.versioner.clone();

        // Extract raw private key bytes
        let (_, raw_private_bytes) = private_key
            .versioner
            .extract(&private_key.bytes)
            .expect("Failed to extract private key bytes");

        // Optional: Check if versions are compatible
        if version != public_key.version {
            // Decide how to handle version mismatch - error or specific logic
            bail!(
                "Private key version {:?} does not match public key version {:?}",
                version,
                public_key.version
            );
        }

        // Derive raw public key bytes
        let raw_public_bytes = public_key
            .signer
            .get_public_key(raw_private_bytes)
            .expect("Failed to derive public key");

        // Attach version
        public_key.bytes = public_key.versioner.attach(version, &raw_public_bytes);

        Ok(public_key)
    }

    /// Returns the versioned public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Serializes the public key to a string (Base58 with prefix).
    pub fn to_string(&self) -> String {
        format!(
            "{}{}",
            PUBLIC_KEY_PREFIX,
            self.serializer.serialize(&self.bytes)
        )
    }

    /// Derives the Address associated with this public key.
    pub fn get_address(&self) -> Result<Address> {
        Address::from_public_key(self)
    }

    /// Verifies a signature against a message (hashes message first).
    /// Note: Matches the non-standard JS behavior of verifying the hash.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let message_hash = self.hasher.hash(message);

        // Extract raw public key bytes
        let (pk_version, raw_public_key) = self.versioner.extract(&self.bytes)?;

        // Extract raw signature bytes
        let binding = signature.to_vec();
        let (sig_version, raw_signature) = self.versioner.extract(&binding)?; // Assuming same versioner

        // Optional: Check if versions are compatible
        if pk_version != sig_version {
            // Decide how to handle version mismatch - error or specific logic
            bail!(
                "Public key version {:?} does not match signature version {:?}",
                pk_version,
                sig_version
            );
        }

        self.signer
            .verify(raw_public_key, &message_hash, raw_signature)
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Define concrete type alias for V0 keys for convenience in tests
    type V0PrivateKey =
        PrivateKey<Blake3Hasher, Ed25519Signer, Base58Serializer, SimplePrefixVersioner>;
    type V0PublicKey =
        PublicKey<Blake3Hasher, Ed25519Signer, Base58Serializer, SimplePrefixVersioner>;
    const PRIVATE_KEY: &str = "S12RJ9WTahqwfmdXeSEUdkgWZUPW7S8qu9RWGc8inuLwiZt1o4s";

    /*
       #[test]
       fn test_sign_and_verify_v0() -> Result<()> {
           let private_key = V0PrivateKey::generate(Version::V0)?;
           let public_key = private_key.get_public_key()?;

           let message = b"This is a test message.";

           let signature = private_key.sign(message)?;
           println!("Signature: {:?}", signature);
           println!("Signature (String): {}", signature.to_string());

           // Check signature length (Version byte + Signature bytes)
           assert_eq!(signature.to_vec().len(), 1 + SIGNATURE_LENGTH); // 1 byte version + 64 byte signature

           // Verification should succeed with the correct key and message
           assert!(public_key.verify(message, &signature)?);

           // Verification should fail with a different message
           let wrong_message = b"This is not the original message.";
           assert!(!public_key.verify(wrong_message, &signature)?);

           // Verification should fail with a different public key
           let other_private_key = V0PrivateKey::generate(Version::V0)?;
           let other_public_key = other_private_key.get_public_key()?;
           assert!(!other_public_key.verify(message, &signature)?);

           Ok(())
       }

       #[test]
       fn test_serialization_deserialization_v0() -> Result<()> {
           let private_key_gen = V0PrivateKey::generate(Version::V0)?;
           let public_key_gen = private_key_gen.get_public_key()?;

           let priv_str = private_key_gen.to_string();
           let pub_str = public_key_gen.to_string();

           println!("Private String: {}", priv_str);
           println!("Public String: {}", pub_str);

           let private_key_deser = V0PrivateKey::from_string(&priv_str)?;
           let public_key_deser = V0PublicKey::from_string(&pub_str)?;

           // Check if internal bytes match after round trip
           assert_eq!(private_key_gen.to_bytes(), private_key_deser.to_bytes());
           assert_eq!(public_key_gen.to_bytes(), public_key_deser.to_bytes());

           // Check if string representations match
           assert_eq!(priv_str, private_key_deser.to_string());
           assert_eq!(pub_str, public_key_deser.to_string());

           // Test byte serialization round trip
           let priv_bytes = private_key_gen.to_bytes();
           let pub_bytes = public_key_gen.to_bytes();

           let private_key_deser_bytes = V0PrivateKey::from_bytes(priv_bytes.clone())?;
           let public_key_deser_bytes = V0PublicKey::from_bytes(pub_bytes.clone())?;

           assert_eq!(priv_bytes, private_key_deser_bytes.to_bytes());
           assert_eq!(pub_bytes, public_key_deser_bytes.to_bytes());

           Ok(())
       }

       #[test]
       fn test_invalid_prefix() {
           let invalid_priv_str = "X12345"; // Invalid prefix
           assert!(V0PrivateKey::from_string(invalid_priv_str).is_err());

           let invalid_pub_str = "S12345"; // Wrong prefix
           assert!(V0PublicKey::from_string(invalid_pub_str).is_err());
       }

       #[test]
       fn test_invalid_base58() {
           let invalid_priv_str = format!("{}InvalidChars!", PRIVATE_KEY_PREFIX);
           assert!(V0PrivateKey::from_string(&invalid_priv_str).is_err());
       }
    */

    #[test]
    fn test_get_address() -> Result<()> {
        let private_key = V0PrivateKey::from_string(PRIVATE_KEY)?;
        println!("Private Key: {}", private_key.to_string());
        let public_key = private_key.get_public_key()?;
        println!("Public Key: {}", public_key.to_string());
        let address = public_key.get_address()?;

        println!("Address: {}", address.to_string());

        Ok(())
    }
}
