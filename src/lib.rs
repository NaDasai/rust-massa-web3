pub mod basic_elements;
pub mod client;
pub mod constants;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::{basic_elements::args::Args, client::grpc_client::PublicGrpcClient};

    use super::*;

    use std::str::FromStr;

    use massa_signature::KeyPair;

    #[tokio::test]
    async fn test_swap_eaglefi_buildnet() {
        let mut client = PublicGrpcClient::new_buildnet()
            .await
            .expect("Failed to create buildnet client");

        let response = client.get_status().await.expect("Failed to get status");

        assert!(response.status.is_some());

        assert_eq!(response.status.unwrap().version, "DEVN.28.12");

        let mut swap_args = Args::new();
    }

    #[test]
    fn test_using_private_key() {
        dotenvy::dotenv().ok();

        let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");

        let key_pair = KeyPair::from_str(&private_key)
            .expect("Failed to create key pair From Private Key string");
        println!("key_pair: {:?}", key_pair);

        assert!(key_pair.to_string() == private_key);

        let public_key = key_pair.get_public_key();
        println!("public_key: {:?}", public_key);
    }
}
