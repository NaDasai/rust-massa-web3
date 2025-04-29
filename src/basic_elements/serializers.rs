use alloy_primitives::U256;

pub fn string_to_bytes(string: &str) -> Vec<u8> {
    string.as_bytes().to_vec()
}

pub fn bytes_to_string(bytes: &Vec<u8>) -> String {
    String::from_utf8(bytes.clone()).expect("Failed to convert bytes to string")
}

pub fn bytes_to_u8(bytes: &Vec<u8>) -> u8 {
    bytes[0]
}

pub fn u8_to_bytes(u8: u8) -> Vec<u8> {
    vec![u8]
}

// Convert a slice of bytes to a u64
pub fn bytes_to_u64(bytes: &Vec<u8>) -> u64 {
    // Take the first 8 bytes of the input vector
    // Convert them to a fixed-size array using try_into()
    // Unwrap the result (this will panic if there are fewer than 8 bytes)
    // Then convert the array to a u64 using from_le_bytes (assuming little-endian byte order)
    u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .expect("Input bytes vector must be at least 8 bytes long for u64"),
    )
}

// Convert a u64 to a vector of bytes
pub fn u64_to_bytes(u64: u64) -> Vec<u8> {
    // Convert the u64 to an array of 8 bytes in little-endian order
    // Then convert this array to a vector
    u64.to_le_bytes().to_vec()
}

// Convert a slice of bytes to a u32
pub fn bytes_to_u32(bytes: &Vec<u8>) -> u32 {
    // Take the first 4 bytes of the input vector
    // Convert them to a fixed-size array using try_into()
    // Unwrap the result (this will panic if there are fewer than 4 bytes)
    // Then convert the array to a u32 using from_le_bytes (assuming little-endian byte order)
    u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .expect("Input bytes vector must be at least 4 bytes long for u32"),
    )
}

// Convert a u32 to a vector of bytes
pub fn u32_to_bytes(u32: u32) -> Vec<u8> {
    // Convert the u32 to an array of 4 bytes in little-endian order
    // Then convert this array to a vector
    u32.to_le_bytes().to_vec()
}

// Convert u16 to bytes

pub fn u16_to_bytes(u16: u16) -> Vec<u8> {
    // Convert the u16 to an array of 2 bytes in little-endian order
    // Then convert this array to a vector
    u16.to_le_bytes().to_vec()
}

// Convert bytes to u16
pub fn bytes_to_u16(bytes: &Vec<u8>) -> u16 {
    // Take the first 2 bytes of the input vector
    // Convert them to a fixed-size array using try_into()
    // Unwrap the result (this will panic if there are fewer than 2 bytes)
    // Then convert the array to a u16 using from_le_bytes (assuming little-endian byte order)
    u16::from_le_bytes(
        bytes[..2]
            .try_into()
            .expect("Input bytes vector must be at least 2 bytes long for u16"),
    )
}

// Convert u256 to bytes
pub fn u256_to_bytes(u256: U256) -> Vec<u8> {
    U256::to_le_bytes_vec(&u256)
}

// Convert bytes to u256
pub fn bytes_to_u256(bytes: &Vec<u8>) -> U256 {
    let mut serializer = [0u8; 32];

    let len = bytes.len().min(32);

    serializer[..len].copy_from_slice(&bytes[..len]);

    U256::from_le_bytes(serializer)
}

#[cfg(test)]
mod tests {
    // Import the parent module
    use super::*;

    #[test]
    fn test_string_to_bytes() {
        let string = "Hello, World!";
        let bytes = string_to_bytes(string);
        assert_eq!(bytes, b"Hello, World!".to_vec());
    }

    #[test]
    fn test_bytes_to_string() {
        let bytes = b"Hello, World!".to_vec();
        let string = bytes_to_string(&bytes);
        assert_eq!(string, "Hello, World!");
    }

    #[test]
    fn test_bytes_to_u8() {
        let bytes = b"Hello, World!".to_vec();
        let u8 = bytes_to_u8(&bytes);
        assert_eq!(u8, 72);
    }

    #[test]
    fn test_u8_to_bytes() {
        let u8 = 72;
        let bytes = u8_to_bytes(u8);
        assert_eq!(bytes, b"H".to_vec());
    }

    #[test]
    fn test_u64_bytes() {
        let number: u64 = 10000;
        let bytes = u64_to_bytes(number);
        let number2 = bytes_to_u64(&bytes);
        println!("number: {}", number);
        println!("bytes: {:?}", bytes);
        println!("number2: {}", number2);
        assert_eq!(number, number2);
    }

    #[test]
    fn test_u32_bytes() {
        let number: u32 = 10000;
        let bytes = u32_to_bytes(number);
        let number2 = bytes_to_u32(&bytes);
        println!("number: {}", number);
        println!("bytes: {:?}", bytes);
        println!("number2: {}", number2);
        assert_eq!(number, number2);
    }

    #[test]
    fn test_u16_bytes() {
        let number: u16 = 10000;
        let bytes = u16_to_bytes(number);
        let number2 = bytes_to_u16(&bytes);
        println!("number: {}", number);
        println!("bytes: {:?}", bytes);
        println!("number2: {}", number2);
        assert_eq!(number, number2);
    }

    #[test]
    fn test_u256_bytes() {
        let number: U256 = U256::from(u64::MAX );
        let bytes = u256_to_bytes(number);
        let number2 = bytes_to_u256(&bytes);
        println!("number: {}", number);
        println!("bytes: {:?}", bytes);
        println!("number2: {}", number2);
        assert_eq!(number, number2);
    }
}
