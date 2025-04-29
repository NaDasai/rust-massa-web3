pub mod basic_elements;
pub mod client;
pub mod constants;
pub mod types;
pub mod crypto;

#[cfg(test)]
mod tests {
    use crate::{basic_elements::args::Args, client::grpc_client::PublicGrpcClient};

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
}
