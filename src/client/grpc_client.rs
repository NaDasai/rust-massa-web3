use std::str::FromStr;

use anyhow::{Context, Error, Result};
use massa_models::{
    address::Address,
    amount::Amount,
    operation::{Operation, OperationSerializer, OperationType, SecureShareOperation},
    secure_share::{SecureShareContent, SecureShareSerializer},
};
use massa_proto_rs::massa::{
    api::v1::{
        GetDatastoreEntriesRequest, GetOperationsRequest, GetStatusRequest, GetStatusResponse,
        SendOperationsRequest, get_datastore_entry_filter,
        public_service_client::PublicServiceClient, send_operations_response,
    },
    model::v1::{AddressKeyEntry, DatastoreEntry, OperationWrapper},
};
use massa_serialization::Serializer;
use massa_signature::KeyPair;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, transport::Channel};

use crate::{
    basic_elements::serializers::string_to_bytes,
    constants::PublicGRPCURL,
    types::{ChainId, ReadStorageKey},
};

pub struct PublicGrpcClient {
    pub client: PublicServiceClient<Channel>,
    pub grpc_url: String,
    pub keypair: Option<KeyPair>,
    pub chain_id: ChainId,
}

impl PublicGrpcClient {
    pub async fn new(
        grpc_url: String,
        chain_id: ChainId,
        keypair: Option<KeyPair>,
    ) -> Result<Self, tonic::transport::Error> {
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self {
            client,
            grpc_url,
            keypair,
            chain_id,
        })
    }

    pub async fn new_buildnet() -> Result<Self, tonic::transport::Error> {
        let grpc_url = PublicGRPCURL::Buildnet.url().to_string();
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self {
            client,
            grpc_url,
            chain_id: ChainId::BUILDNET,
            keypair: None,
        })
    }

    pub async fn new_mainnet() -> Result<Self, tonic::transport::Error> {
        let grpc_url = PublicGRPCURL::Mainnet.url().to_string();
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self {
            client,
            grpc_url,
            chain_id: ChainId::MAINNET,
            keypair: None,
        })
    }

    pub async fn new_from_env() -> Result<Self, tonic::transport::Error> {
        dotenvy::dotenv().ok();

        let grpc_url = std::env::var("MASSA_GRPC_URL").expect("MASSA_GRPC_URL not set");
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        // Try to get the private key from the environment
        match std::env::var("PRIVATE_KEY") {
            Ok(private_key) => {
                // Create a key pair from the private key
                let keypair = KeyPair::from_str(&private_key)
                    .expect("Failed to create key pair from private key");

                return Ok(Self {
                    client,
                    grpc_url,
                    chain_id: ChainId::BUILDNET,
                    keypair: Some(keypair),
                });
            }

            Err(_) => Ok(Self {
                client,
                grpc_url,
                chain_id: ChainId::BUILDNET,
                keypair: None,
            }),
        }
    }

    pub async fn set_keypair(&mut self, private_key: &str) -> Result<(), Error> {
        self.keypair = Some(
            KeyPair::from_str(private_key).context("Failed to create key pair from private key")?,
        );

        Ok(())
    }

    pub async fn set_chain_id(&mut self, chain_id: ChainId) -> Result<(), Error> {
        self.chain_id = chain_id;

        Ok(())
    }

    pub async fn get_status(&mut self) -> Result<GetStatusResponse, tonic::Status> {
        let request = Request::new(GetStatusRequest {});

        let response = self.client.get_status(request).await?.into_inner();

        Ok(response)
    }

    pub async fn call_sc(
        &mut self,
        smart_contract_address: &str,
        function_name: &str,
        args: Vec<u8>,
        fee: f64,
        max_gas: u64,
        coins: f64,
        expire_period: u64,
    ) -> Result<String, Error> {
        if self.keypair.is_none() {
            return Err(Error::msg("No keypair provided."));
        }

        let keypair = self.keypair.as_ref().context("Failed to get keypair")?;
        let coins = Amount::from_str(&coins.to_string())?;

        let operation_type = OperationType::CallSC {
            target_addr: Address::from_str(smart_contract_address)?,
            target_func: function_name.to_string(),
            param: args,
            max_gas,
            coins,
        };

        println!("Fee inside: {:?}", Amount::from_str(&fee.to_string())?);

        let operation = Operation {
            fee: Amount::from_str(&fee.to_string())?,
            op: operation_type,
            expire_period,
        };

        let secured: SecureShareOperation = massa_models::operation::Operation::new_verifiable(
            operation,
            OperationSerializer::new(),
            &keypair,
            self.chain_id.to_u64(),
        )
        .context("Failed to create verifiable operation")?;

        let mut serialized_data = Vec::new();

        SecureShareSerializer::new()
            .serialize(&secured, &mut serialized_data)
            .context("Failed to serialize operation")?;

        let sned_operations_request = SendOperationsRequest {
            operations: vec![serialized_data],
        };

        // Create an MPSC channel with a buffer size of 128.
        // This allows up to 128 messages to be buffered without blocking the sender.
        // If the receiver doesn't consume messages fast enough, sending will await (apply backpressure).
        // Adjust the buffer size based on expected message rate and latency tolerance.
        let (tx, rx) = mpsc::channel(128);

        let ack = ReceiverStream::new(rx);

        let request = Request::new(ack);

        let response = self
            .client
            .send_operations(request)
            .await
            .context("Failed to send operations to the client")?;

        tx.send(sned_operations_request)
            .await
            .context("Failed to send operations using the channel")?;

        let mut response_stream = response.into_inner();

        while let Some(res) = response_stream
            .message()
            .await
            .context("Failed to get message from send operations stream")?
        {
            // Handle the response here
            // This is the result field from the SendOperationsResponse
            let result = res
                .result
                .context("Failed to get result from send operations response")?;

            match result {
                send_operations_response::Result::Error(e) => {
                    return Err(Error::msg(format!("{:?}", e)));
                }
                send_operations_response::Result::OperationIds(operations) => {
                    dbg!(&operations.operation_ids);

                    // Return the first operation id
                    return Ok(operations.operation_ids[0].clone());
                }
            }
        }

        // If the loop completes without returning, return an error
        Err(Error::msg(
            "No valid operation ID received from the response stream",
        ))
    }

    pub async fn read_storage_key(
        &mut self,
        storage_keys: Vec<ReadStorageKey>,
    ) -> Result<Vec<DatastoreEntry>, tonic::Status> {
        let mut datastores_entries_filters = Vec::new();

        // Loop on all storage keys and call the read_storage_key function
        for storage_key in storage_keys {
            let key_bytes = string_to_bytes(&storage_key.key);

            let key_entry = AddressKeyEntry {
                address: storage_key.smart_contract_address,
                key: key_bytes,
            };

            let datastore_entry_filter = massa_proto_rs::massa::api::v1::GetDatastoreEntryFilter {
                filter: Some(get_datastore_entry_filter::Filter::AddressKey(key_entry)),
            };

            datastores_entries_filters.push(datastore_entry_filter);
        }

        let request = GetDatastoreEntriesRequest {
            filters: datastores_entries_filters,
        };

        let response = self.client.get_datastore_entries(request).await?;

        let entries_result = response.into_inner().datastore_entries;

        Ok(entries_result)
    }

    pub async fn get_operations(
        &mut self,
        operation_ids: Vec<String>,
    ) -> Result<Vec<OperationWrapper>, tonic::Status> {
        let request = Request::new(GetOperationsRequest {
            operation_ids: operation_ids.clone(),
        });

        let response = self.client.get_operations(request).await?.into_inner();

        let operations = response.wrapped_operations;

        Ok(operations)
    }
}

#[cfg(test)]
mod tests {
    use crate::basic_elements::args::Args;

    // Import the parent module
    use super::*;

    #[tokio::test]
    async fn test_get_status() {
        let mut client = PublicGrpcClient::new_buildnet().await.unwrap();
        let response = client.get_status().await.unwrap();

        // Assert response.status is not none
        assert!(response.status.is_some());

        // Assert response.status.version is "DEVN.28.12"
        assert_eq!(response.status.unwrap().version, "DEVN.28.12");
    }

    /* #[tokio::test]
    async fn test_call_sc() {
        dotenvy::dotenv().ok();

        let fee = 0.01;
        let max_gas = (u32::MAX - 1) as u64;
        let target_address = "AS12gSdL2EZH5Mj4UAFuk69aiYPuKoH1sK982oEDQfwxu97sAT9js";
        let target_function = "addLiquidity";
        let parameter = Vec::new();
        let coins: f64 = 0.0;
        let expire_period = 2607115 + 100000;

        let mut client = PublicGrpcClient::new_buildnet()
            .await
            .expect("Failed to create client");

        let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");

        client
            .set_keypair(&private_key)
            .await
            .expect("Failed to set keypair");

        let operation_id = client
            .call_sc(
                target_address,
                target_function,
                parameter,
                fee,
                max_gas,
                coins,
                expire_period,
            )
            .await
            .expect("Failed to call smart contract");

        println!("Operation ID: {}", operation_id);
    } */

    #[tokio::test]
    async fn test_set_name() {
        let mut client = PublicGrpcClient::new_from_env()
            .await
            .expect("Failed to create client");

        let target_function = "setName";
        let fee = 0.1;
        dbg!(&fee);
        let max_gas = (u32::MAX - 1) as u64;
        let target_address = "AS12ZmE7e8TSTcDBGYpUBCDhAR85Ts6b9Rf3aKTAmRXV8FC6PN4JK";
        let coins: f64 = 0.01;
        let expire_period = 2607968 + 20000;

        // let parameter = Args::new().add_string("test").serialize();
        let parameter = Vec::new();

        let operation_id = client
            .call_sc(
                target_address,
                target_function,
                parameter,
                fee,
                max_gas,
                coins,
                expire_period,
            )
            .await
            .expect("Failed to call smart contract");

        println!("Operation ID of setting name: {}", operation_id);

        // trying to get operation
        let operations = client
            .get_operations(vec![operation_id])
            .await
            .expect("Failed to get operations");

        println!("Operations: {:?}", operations);
    }
}
