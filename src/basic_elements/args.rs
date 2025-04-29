use alloy_primitives::U256;
use anyhow::{Context, Result, anyhow, bail};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

use crate::types::ArrayType;

use super::next_arg::NextArg; // Cursor allows treating &[u8] like a reader

// 32 / 8 bits = 4 bytes
pub const BYTES_32_OFFSET: usize = 4;
// 64 / 8 bits = 8 bytes
pub const BYTES_64_OFFSET: usize = 8;
// 128 / 8 bits = 16 bytes
pub const BYTES_128_OFFSET: usize = 16;
// 256 / 8 bits = 32 bytes
pub const BYTES_256_OFFSET: usize = 32;
pub const DEFAULT_OFFSET: usize = 0;

// --- Serializable Trait (Equivalent to JS Serializable<T>) ---
// We need a way to define how custom types are serialized/deserialized.
pub trait Serializable: Sized {
    // Serializes the object into a byte vector
    fn serialize(&self) -> Vec<u8>;

    // Deserializes from a byte slice starting at a given offset.
    // Returns the deserialized object and the new offset after reading.
    fn deserialize(data: &[u8], offset: usize) -> Result<(Self, usize)>;
}

#[derive(Debug, Clone)]
pub struct Args {
    serialized: Vec<u8>,
    offset: usize, // For deserialization
}

impl Args {
    pub fn new() -> Self {
        Self {
            serialized: Vec::new(),
            offset: DEFAULT_OFFSET,
        }
    }

    /// Creates Args from existing serialized data, ready for deserialization.
    pub fn from_bytes(serialized: Vec<u8>) -> Self {
        Self {
            serialized,
            offset: DEFAULT_OFFSET,
        }
    }

    /// Returns the current deserialization offset.
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.serialized.clone()
    }

    /// Returns a reference to the underlying serialized data.
    pub fn get_serialized_buffer(&self) -> &[u8] {
        &self.serialized
    }

    // --- Internal Helper for Reading ---
    /// Reads a specific number of bytes from the current offset.
    /// Advances the offset. Returns an error if not enough bytes are available.
    fn read_bytes(&mut self, len: usize) -> Result<&[u8]> {
        let current_offset = self.offset;
        let end_offset = current_offset.checked_add(len).ok_or_else(|| {
            anyhow!(
                "Offset overflow while trying to read {} bytes from offset {}",
                len,
                current_offset
            )
        })?;

        if end_offset > self.serialized.len() {
            bail!(
                "Not enough bytes to read. Wanted {} bytes from offset {}, but buffer length is {}",
                len,
                current_offset,
                self.serialized.len()
            );
        }

        self.offset = end_offset;
        Ok(&self.serialized[current_offset..end_offset])
    }

    // --- Deserialization Methods (`next*`) ---

    /// Reads the next u8 from the buffer.
    pub fn next_u8(&mut self) -> Result<u8> {
        self.read_bytes(1)?.read_u8().context("Failed to read u8")
    }

    /// Reads the next u16 (Little Endian) from the buffer.
    pub fn next_u16(&mut self) -> Result<u16> {
        self.read_bytes(2)?
            .read_u16::<LittleEndian>()
            .context("Failed to read u16")
    }

    /// Reads the next u32 (Little Endian) from the buffer.
    pub fn next_u32(&mut self) -> Result<u32> {
        self.read_bytes(BYTES_32_OFFSET)?
            .read_u32::<LittleEndian>()
            .context("Failed to read u32")
    }

    /// Reads the next u64 (Little Endian) from the buffer.
    pub fn next_u64(&mut self) -> Result<u64> {
        self.read_bytes(BYTES_64_OFFSET)?
            .read_u64::<LittleEndian>()
            .context("Failed to read u64")
    }

    /// Reads the next u128 (Little Endian) from the buffer.
    pub fn next_u128(&mut self) -> Result<u128> {
        self.read_bytes(BYTES_128_OFFSET)?
            .read_u128::<LittleEndian>()
            .context("Failed to read u128")
    }

    /// Reads the next u256 (Little Endian) from the buffer.
    pub fn next_u256(&mut self) -> Result<U256> {
        // Use U256 from alloy_primitives
        // Read 32 bytes
        // Convert to U256
        let le_bytes = self
            .read_bytes(BYTES_256_OFFSET)
            .context("Failed to read u256")?;

        let mut serializer = [0u8; 32];

        serializer.copy_from_slice(le_bytes);

        Ok(U256::from_le_bytes(serializer))
    }

    /// Reads the next i8 from the buffer.
    pub fn next_i8(&mut self) -> Result<i8> {
        self.read_bytes(1)?.read_i8().context("Failed to read i8")
    }

    /// Reads the next i16 (Little Endian) from the buffer.
    pub fn next_i16(&mut self) -> Result<i16> {
        self.read_bytes(2)?
            .read_i16::<LittleEndian>()
            .context("Failed to read i16")
    }

    /// Reads the next i32 (Little Endian) from the buffer.
    pub fn next_i32(&mut self) -> Result<i32> {
        self.read_bytes(BYTES_32_OFFSET)?
            .read_i32::<LittleEndian>()
            .context("Failed to read i32")
    }

    /// Reads the next i64 (Little Endian) from the buffer.
    pub fn next_i64(&mut self) -> Result<i64> {
        self.read_bytes(BYTES_64_OFFSET)?
            .read_i64::<LittleEndian>()
            .context("Failed to read i64")
    }

    /// Reads the next f32 (Little Endian) from the buffer.
    pub fn next_f32(&mut self) -> Result<f32> {
        self.read_bytes(BYTES_32_OFFSET)?
            .read_f32::<LittleEndian>()
            .context("Failed to read f32")
    }

    /// Reads the next f64 (Little Endian) from the buffer.
    pub fn next_f64(&mut self) -> Result<f64> {
        self.read_bytes(BYTES_64_OFFSET)?
            .read_f64::<LittleEndian>()
            .context("Failed to read f64")
    }

    /// Reads the next boolean from the buffer (reads a u8, non-zero is true).
    pub fn next_bool(&mut self) -> Result<bool> {
        let val = self.next_u8()?;
        Ok(val != 0)
    }

    /// Reads the next string from the buffer (reads length as u32, then UTF-8 bytes).
    pub fn next_string(&mut self) -> Result<String> {
        let len = self.next_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .with_context(|| format!("Failed to decode UTF-8 string with length {}", len))
    }

    /// Reads the next byte array from the buffer (reads length as u32, then bytes).
    pub fn next_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.next_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        Ok(bytes.to_vec())
    }

    /// Alias for next_bytes to match JS naming.
    pub fn next_uint8array(&mut self) -> Result<Vec<u8>> {
        self.next_bytes()
    }

    /// Reads the next object implementing `Serializable`.
    pub fn next_serializable<T: Serializable>(&mut self) -> Result<T> {
        // The Serializable::deserialize implementation handles reading its own bytes
        // and returning the new offset.
        let (instance, new_offset) = T::deserialize(&self.serialized, self.offset)?;
        // Check if the returned offset is valid
        if new_offset < self.offset || new_offset > self.serialized.len() {
            bail!(
                "Invalid offset {} returned by {}::deserialize (previous offset {}, buffer length {})",
                new_offset,
                std::any::type_name::<T>(),
                self.offset,
                self.serialized.len()
            );
        }
        self.offset = new_offset;
        Ok(instance)
    }

    /// Reads an array of simple types (numbers, bools).
    /// Note: String arrays need special handling due to variable length.
    /// This example uses a simple match; more complex scenarios might need generics
    /// or trait bounds.
    pub fn next_array<T>(&mut self, element_type: ArrayType) -> Result<Vec<T>>
    where
        T: Default + Clone + 'static, // Basic bounds, adjust as needed
        Args: NextArg<T>,             // Requires implementing a helper trait
    {
        let len = self.next_u32()? as usize;
        let mut result = Vec::with_capacity(len);
        // We need a way to call the correct `next_` method based on `element_type`
        // This is tricky without runtime type information or complex generics/macros.
        // The JS version likely uses a switch statement.
        // A simpler Rust approach is to have specific methods like `next_u32_array`.
        // Or use a helper trait as shown below.
        for _ in 0..len {
            // This requires the `NextArg` trait defined below
            result.push(self.next_arg(element_type)?);
        }
        Ok(result)
    }

    // Specific array readers are often clearer in Rust:
    pub fn next_u32_array(&mut self) -> Result<Vec<u32>> {
        let len = self.next_u32()? as usize;
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push(self.next_u32()?);
        }
        Ok(result)
    }

    pub fn next_string_array(&mut self) -> Result<Vec<String>> {
        let len = self.next_u32()? as usize;
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push(self.next_string()?);
        }
        Ok(result)
    }

    /// Reads an array of objects implementing `Serializable`.
    pub fn next_serializable_object_array<T: Serializable>(&mut self) -> Result<Vec<T>> {
        let total_byte_len = self.next_u32()? as usize; // Read the total byte length of the serialized array content
        let target_offset = self.offset + total_byte_len;

        if target_offset > self.serialized.len() {
            bail!(
                "Serializable array length ({}) exceeds buffer bounds (offset {}, len {})",
                total_byte_len,
                self.offset,
                self.serialized.len()
            );
        }

        let mut result = Vec::new();
        while self.offset < target_offset {
            // Deserialize each object. The offset is advanced internally by next_serializable.
            let obj = self.next_serializable::<T>()?;
            result.push(obj);
        }

        // Ensure we consumed exactly the expected number of bytes
        if self.offset != target_offset {
            bail!(
                "Deserializing serializable array consumed {} bytes, but expected {}",
                self.offset - (target_offset - total_byte_len),
                total_byte_len
            );
        }

        Ok(result)
    }

    // --- Serialization Methods (`add*`) ---

    /// Adds a u8 to the buffer.
    pub fn add_u8(&mut self, value: u8) -> &mut Self {
        self.serialized.write_u8(value).unwrap(); // Writing to Vec<u8> shouldn't fail
        self
    }

    /// Adds a u16 (Little Endian) to the buffer.
    pub fn add_u16(&mut self, value: u16) -> &mut Self {
        self.serialized.write_u16::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds a u32 (Little Endian) to the buffer.
    pub fn add_u32(&mut self, value: u32) -> &mut Self {
        self.serialized.write_u32::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds a u64 (Little Endian) to the buffer.
    pub fn add_u64(&mut self, value: u64) -> &mut Self {
        self.serialized.write_u64::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds a u128 (Little Endian) to the buffer.
    pub fn add_u128(&mut self, value: u128) -> &mut Self {
        self.serialized.write_u128::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds a u256 (Little Endian) to the buffer.
    pub fn add_u256(&mut self, value: U256) -> &mut Self {
        self.serialized.extend_from_slice(&value.to_le_bytes_vec());
        self
    }

    /// Adds an i8 to the buffer.
    pub fn add_i8(&mut self, value: i8) -> &mut Self {
        self.serialized.write_i8(value).unwrap();
        self
    }

    /// Adds an i16 (Little Endian) to the buffer.
    pub fn add_i16(&mut self, value: i16) -> &mut Self {
        self.serialized.write_i16::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds an i32 (Little Endian) to the buffer.
    pub fn add_i32(&mut self, value: i32) -> &mut Self {
        self.serialized.write_i32::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds an i64 (Little Endian) to the buffer.
    pub fn add_i64(&mut self, value: i64) -> &mut Self {
        self.serialized.write_i64::<LittleEndian>(value).unwrap();
        self
    }

    // Add add_i128, add_i256 using appropriate crates if needed

    /// Adds an f32 (Little Endian) to the buffer.
    pub fn add_f32(&mut self, value: f32) -> &mut Self {
        self.serialized.write_f32::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds an f64 (Little Endian) to the buffer.
    pub fn add_f64(&mut self, value: f64) -> &mut Self {
        self.serialized.write_f64::<LittleEndian>(value).unwrap();
        self
    }

    /// Adds a boolean to the buffer (as a u8: 1 for true, 0 for false).
    pub fn add_bool(&mut self, value: bool) -> &mut Self {
        self.add_u8(if value { 1 } else { 0 });
        self
    }

    /// Adds a string to the buffer (length as u32, then UTF-8 bytes).
    pub fn add_string(&mut self, value: &str) -> &mut Self {
        let bytes = value.as_bytes();
        // Check max size if necessary, like JS
        const MAX_SIZE: usize = u32::MAX as usize;
        if bytes.len() > MAX_SIZE {
            // Decide how to handle: panic, truncate, return error?
            // JS warns and truncates, let's panic for now as it's likely an error.
            panic!(
                "String length {} exceeds maximum allowed size {}",
                bytes.len(),
                MAX_SIZE
            );
            // Or truncate:
            // let bytes = &bytes[0..MAX_SIZE];
        }
        self.add_u32(bytes.len() as u32); // Add length prefix
        self.serialized.extend_from_slice(bytes); // Add string bytes
        self
    }

    /// Adds a byte array (`&[u8]`) to the buffer (length as u32, then bytes).
    pub fn add_bytes(&mut self, value: &[u8]) -> &mut Self {
        const MAX_SIZE: usize = u32::MAX as usize;
        if value.len() > MAX_SIZE {
            panic!(
                "Byte array length {} exceeds maximum allowed size {}",
                value.len(),
                MAX_SIZE
            );
        }
        self.add_u32(value.len() as u32); // Add length prefix
        self.serialized.extend_from_slice(value); // Add bytes
        self
    }

    /// Alias for add_bytes to match JS naming.
    pub fn add_uint8array(&mut self, value: &[u8]) -> &mut Self {
        self.add_bytes(value)
    }

    /// Adds an object implementing `Serializable`.
    pub fn add_serializable<T: Serializable>(&mut self, value: &T) -> &mut Self {
        let bytes = value.serialize();
        // Note: The JS version doesn't length-prefix individual serializables,
        // only arrays of them. We follow that pattern.
        self.serialized.extend_from_slice(&bytes);
        self
    }

    /// Adds an array of simple types. This requires specific implementations
    /// or more complex generics/traits. Let's provide specific versions.
    pub fn add_u32_array(&mut self, values: &[u32]) -> &mut Self {
        self.add_u32(values.len() as u32); // Length prefix for the number of elements
        for &value in values {
            self.add_u32(value);
        }
        self
    }

    pub fn add_string_array(&mut self, values: &[String]) -> &mut Self {
        self.add_u32(values.len() as u32); // Length prefix for the number of elements
        for value in values {
            self.add_string(value); // Each string includes its own length prefix
        }
        self
    }
    // etc. for other types...

    /// Adds an array of objects implementing `Serializable`.
    pub fn add_serializable_object_array<T: Serializable>(&mut self, values: &[T]) -> &mut Self {
        // 1. Serialize all objects into a temporary buffer to get the total byte length.
        let mut content_buf = Vec::new();
        for value in values {
            content_buf.extend_from_slice(&value.serialize());
        }

        // 2. Add the total byte length as a u32 prefix.
        const MAX_SIZE: usize = u32::MAX as usize;
        if content_buf.len() > MAX_SIZE {
            panic!(
                "Total byte length of serializable array {} exceeds maximum allowed size {}",
                content_buf.len(),
                MAX_SIZE
            );
        }
        self.add_u32(content_buf.len() as u32);

        // 3. Add the concatenated serialized objects.
        self.serialized.extend_from_slice(&content_buf);
        self
    }

    pub fn _get_serialized(&self) -> &[u8] {
        &self.serialized
    }
}

// --- Example Usage and Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    // Example struct implementing Serializable
    #[derive(Debug, PartialEq, Clone)]
    struct Point {
        x: i32,
        y: i32,
    }

    impl Serializable for Point {
        fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.write_i32::<LittleEndian>(self.x).unwrap();
            buf.write_i32::<LittleEndian>(self.y).unwrap();
            buf
        }

        fn deserialize(data: &[u8], offset: usize) -> Result<(Self, usize)> {
            let mut cursor = Cursor::new(&data[offset..]);
            let x = cursor
                .read_i32::<LittleEndian>()
                .context("Failed to read Point.x")?;
            let y = cursor
                .read_i32::<LittleEndian>()
                .context("Failed to read Point.y")?;
            let bytes_read = cursor.position() as usize;
            Ok((Point { x, y }, offset + bytes_read))
        }
    }

    #[test]
    fn test_add_and_next_primitives() -> Result<()> {
        let mut args = Args::new();
        args.add_u8(10)
            .add_i32(-500)
            .add_bool(true)
            .add_f64(123.456);

        let mut reader_args = Args::from_bytes(args.serialize());
        assert_eq!(reader_args.next_u8()?, 10);
        assert_eq!(reader_args.next_i32()?, -500);
        assert_eq!(reader_args.next_bool()?, true);
        assert_eq!(reader_args.next_f64()?, 123.456);
        // Check final offset, it should be the sum of all added bytes
        assert_eq!(reader_args.get_offset(), 1 + 4 + 1 + 8); // Check final offset

        Ok(())
    }

    #[test]
    fn test_add_and_next_string() -> Result<()> {
        let mut args = Args::new();
        let s1 = "hello";
        let s2 = "world!";
        args.add_string(s1).add_string(s2);

        let mut reader_args = Args::from_bytes(args.serialize());
        assert_eq!(reader_args.next_string()?, s1);
        assert_eq!(reader_args.next_string()?, s2);
        assert_eq!(reader_args.get_offset(), (4 + s1.len()) + (4 + s2.len()));

        Ok(())
    }

    #[test]
    fn test_add_and_next_bytes() -> Result<()> {
        let mut args = Args::new();
        let b1: Vec<u8> = vec![1, 2, 3];
        let b2: Vec<u8> = vec![10, 20];
        args.add_bytes(&b1).add_uint8array(&b2);

        let mut reader_args = Args::from_bytes(args.serialize());
        assert_eq!(reader_args.next_bytes()?, b1);
        assert_eq!(reader_args.next_uint8array()?, b2);
        assert_eq!(reader_args.get_offset(), (4 + b1.len()) + (4 + b2.len()));

        Ok(())
    }

    #[test]
    fn test_add_and_next_serializable() -> Result<()> {
        let mut args = Args::new();
        let p1 = Point { x: 1, y: 2 };
        let p2 = Point { x: -10, y: -20 };
        args.add_serializable(&p1).add_serializable(&p2);

        let mut reader_args = Args::from_bytes(args.serialize());
        assert_eq!(reader_args.next_serializable::<Point>()?, p1);
        assert_eq!(reader_args.next_serializable::<Point>()?, p2);
        // Point is 2 * i32 = 8 bytes
        assert_eq!(reader_args.get_offset(), 8 + 8);

        Ok(())
    }

    #[test]
    fn test_add_and_next_serializable_array() -> Result<()> {
        let mut args = Args::new();
        let points = vec![
            Point { x: 1, y: 2 },
            Point { x: 3, y: 4 },
            Point { x: 5, y: 6 },
        ];
        args.add_serializable_object_array(&points);

        let mut reader_args = Args::from_bytes(args.serialize());
        let deserialized_points = reader_args.next_serializable_object_array::<Point>()?;

        assert_eq!(deserialized_points, points);
        // 4 bytes for length prefix + 3 points * 8 bytes/point
        assert_eq!(reader_args.get_offset(), 4 + 3 * 8);

        Ok(())
    }

    #[test]
    fn test_add_and_next_u32_array() -> Result<()> {
        let mut args = Args::new();
        let data: Vec<u32> = vec![10, 20, 30, 40];
        args.add_u32_array(&data);

        let mut reader_args = Args::from_bytes(args.serialize());
        let deserialized_data = reader_args.next_u32_array()?;
        assert_eq!(deserialized_data, data);
        // 4 bytes for array length + 4 elements * 4 bytes/u32
        assert_eq!(reader_args.get_offset(), 4 + 4 * 4);

        Ok(())
    }

    #[test]
    fn test_add_and_next_string_array() -> Result<()> {
        let mut args = Args::new();
        let data: Vec<String> = vec!["a".to_string(), "bb".to_string(), "ccc".to_string()];
        args.add_string_array(&data);

        let mut reader_args = Args::from_bytes(args.serialize());
        let deserialized_data = reader_args.next_string_array()?;
        assert_eq!(deserialized_data, data);
        // 4 bytes for array length
        // + (4 + 1) for "a"
        // + (4 + 2) for "bb"
        // + (4 + 3) for "ccc"
        assert_eq!(reader_args.get_offset(), 4 + (4 + 1) + (4 + 2) + (4 + 3));

        Ok(())
    }

    #[test]
    fn test_read_past_end() {
        let mut args = Args::new();
        args.add_u8(1).add_u8(2); // Only 2 bytes

        let mut reader_args = Args::from_bytes(args.serialize());
        assert!(reader_args.next_u8().is_ok());
        assert!(reader_args.next_u8().is_ok());
        assert!(reader_args.next_u8().is_err()); // Try to read a third byte
    }

    #[test]
    fn test_read_string_not_enough_data_for_content() {
        let mut args = Args::new();
        args.add_u32(10); // Say length is 10
        args.serialized.push(1); // But only provide 1 byte of content
        args.serialized.push(2);

        let mut reader_args = Args::from_bytes(args.serialize());
        assert!(reader_args.next_string().is_err());
    }

    #[test]
    fn test_read_string_not_enough_data_for_length() {
        let mut args = Args::new();
        args.serialized.push(1); // Only 1 byte, cannot read u32 length

        let mut reader_args = Args::from_bytes(args.serialize());
        assert!(reader_args.next_string().is_err());
    }
}
