use anyhow::Result;
use massa_proto_rs::massa::{
    api::v1::{
        GetDatastoreEntriesRequest, GetStatusRequest, GetStatusResponse,
        get_datastore_entry_filter, public_service_client::PublicServiceClient,
    },
    model::v1::{AddressKeyEntry, DatastoreEntry},
};
use tonic::{Request, transport::Channel};

use crate::{
    basic_elements::serializers::string_to_bytes, constants::PublicGRPCURL, types::ReadStorageKey,
};

pub struct PublicGrpcClient {
    pub client: PublicServiceClient<Channel>,
    pub grpc_url: String,
}

impl PublicGrpcClient {
    pub async fn new(grpc_url: String) -> Result<Self, tonic::transport::Error> {
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self { client, grpc_url })
    }

    pub async fn new_buildnet() -> Result<Self, tonic::transport::Error> {
        let grpc_url = PublicGRPCURL::Buildnet.url().to_string();
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self { client, grpc_url })
    }

    pub async fn new_mainnet() -> Result<Self, tonic::transport::Error> {
        let grpc_url = PublicGRPCURL::Mainnet.url().to_string();
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self { client, grpc_url })
    }

    pub async fn new_from_env() -> Result<Self, tonic::transport::Error> {
        let grpc_url = std::env::var("MASSA_GRPC_URL").expect("MASSA_GRPC_URL not set");
        let client = PublicServiceClient::connect(grpc_url.clone()).await?;

        Ok(Self { client, grpc_url })
    }

    pub async fn get_status(&mut self) -> Result<GetStatusResponse, tonic::Status> {
        let request = Request::new(GetStatusRequest {});

        let response = self.client.get_status(request).await?.into_inner();

        Ok(response)
    }

    pub async fn read_storage_key(
        &mut self,
        storage_keys: Vec<ReadStorageKey>,
    ) -> Result<Vec<DatastoreEntry>, tonic::Status> {
        let mut datastores_entries_filters = Vec::new();

        // Loop on all storage keys and call the read_storage_key function
        for storage_key in storage_keys {
            let key_bytes = string_to_bytes(storage_key.key);

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
}

#[cfg(test)]
mod tests {
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
}
