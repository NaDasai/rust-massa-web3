pub mod basic_elements;
pub mod client;
pub mod constants;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::{basic_elements::{args::Args, serializers::u64_to_bytes}, client::grpc_client::PublicGrpcClient};

    use super::*;

    use std::str::FromStr;

    use massa_proto_rs::massa::{
        api::v1::{SendOperationsRequest, SendOperationsResponse},
        model::v1::{CallSc, NativeAmount, Operation, OperationType, operation_type::Type},
    };
    use massa_signature::KeyPair;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::Request;

    #[tokio::test]
    async fn test_swap_eaglefi_buildnet() {
        let mut client = PublicGrpcClient::new_buildnet()
            .await
            .expect("Failed to create buildnet client");

        dotenvy::dotenv().ok();

        let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");

        let key_pair = KeyPair::from_str(&private_key)
            .expect("Failed to create key pair From Private Key string");
        println!("key_pair: {:?}", key_pair);

        assert!(key_pair.to_string() == private_key);

        let public_key = key_pair.get_public_key();

        println!("public_key: {:?}", public_key);

        let response = client.get_status().await.expect("Failed to get status");

        assert!(response.status.is_some());

        assert_eq!(response.status.unwrap().version, "DEVN.28.12");

        let mut swap_args = Args::new();

        // create operation

        let expire_period = 0;
        let fee = 0;


        let op: OperationType = OperationType {
            r#type: Some(Type::CallSc(CallSc {
                target_address: "AS12gSdL2EZH5Mj4UAFuk69aiYPuKoH1sK982oEDQfwxu97sAT9js".to_string(),
                target_function: "addLiquidity".to_string(),
                parameter: vec![],
                max_gas: (u32::MAX - 1) as u64,
                coins: None,
            })),
        };

        let expire_period = 0;

        let content = Operation {
            fee: Some(NativeAmount::default()),
            expire_period,
            op: Some(op),
        };

        // Serialize the content to vec u8
        let mut serialized_content: Vec<u8> = vec![];

        // serialized_content.push(u64_to_bytes());

        let mut massa_client = client.client;

        let send_operations_request = SendOperationsRequest { operations: vec![] };

        // Create an MPSC channel with a buffer size of 128.
        // This allows up to 128 messages to be buffered without blocking the sender.
        // If the receiver doesn't consume messages fast enough, sending will await (apply backpressure).
        // Adjust the buffer size based on expected message rate and latency tolerance.
        let (tx, rx) = mpsc::channel(128);

        let ack = ReceiverStream::new(rx);

        let request = Request::new(ack);

        let response = massa_client
            .send_operations(request)
            .await
            .expect("Failed to send operations");

        tx.send(send_operations_request)
            .await
            .expect("Failed to send operations");

        let mut response_stream = response.into_inner();

        while let Some(item) = response_stream
            .message()
            .await
            .expect("Failed to get message")
        {
            println!("Received: {:?}", item);
        }
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
