use std::str::FromStr;

use alloy_primitives::{U256, utils::format_units};
use anyhow::{Context, Error, Result, anyhow};
use massa_models::{
    address::Address,
    amount::Amount,
    operation::{Operation, OperationSerializer, OperationType, SecureShareOperation},
    secure_share::{SecureShareContent, SecureShareSerializer},
};
use massa_proto_rs::massa::{
    api::v1::{
        AddressBalanceCandidate, AddressDatastoreKeysFinal, ExecutedOpsChangesFilter,
        ExecutionQueryRequestItem, GetDatastoreEntriesRequest, GetOperationsRequest,
        GetScExecutionEventsRequest, GetStatusRequest, NewSlotExecutionOutputsFilter,
        NewSlotExecutionOutputsRequest, OpExecutionStatusCandidate, OpExecutionStatusFinal,
        QueryStateRequest, ScExecutionEventsFilter, SendOperationsRequest,
        executed_ops_changes_filter, execution_query_request_item, execution_query_response,
        execution_query_response_item, get_datastore_entry_filter,
        new_slot_execution_outputs_filter, public_service_client::PublicServiceClient,
        sc_execution_events_filter, send_operations_response,
    },
    model::v1::{
        AddressKeyEntry, DatastoreEntry, ExecutionOutputStatus, NativeAmount, OperationWrapper,
        PublicStatus, ScExecutionEvent,
    },
};
use massa_serialization::Serializer;
use massa_signature::KeyPair;
use rand::rand_core::le;
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Request, transport::Channel};

use crate::{
    basic_elements::serializers::{bytes_to_string, string_to_bytes},
    constants::{PERIOD_TO_LIVE_DEFAULT, PublicGRPCURL},
    types::{ChainId, ReadStorageKey},
};

#[derive(Debug, Clone)]
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

    pub fn get_current_address(&mut self) -> Result<Address> {
        let keypair = self.keypair.as_ref().context("Failed to get keypair")?;

        let public_key = keypair.get_public_key();

        let address = Address::from_public_key(&public_key);

        Ok(address)
    }

    pub async fn get_status(&mut self) -> Result<PublicStatus> {
        let request = Request::new(GetStatusRequest {});

        let response = self.client.get_status(request).await?.into_inner();

        let status = response.status.context("Failed to get status")?;

        Ok(status)
    }

    pub async fn call_sc(
        &mut self,
        smart_contract_address: &str,
        function_name: &str,
        args: Vec<u8>,
        fee: &str,
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

        let operation = Operation {
            fee: Amount::from_str(fee)?,
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
    ) -> Result<Vec<DatastoreEntry>> {
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
    ) -> Result<Vec<OperationWrapper>> {
        let request = Request::new(GetOperationsRequest {
            operation_ids: operation_ids.clone(),
        });

        let response = self.client.get_operations(request).await?.into_inner();

        let operations = response.wrapped_operations;

        Ok(operations)
    }

    pub async fn get_minimal_fee(&mut self) -> Result<Option<NativeAmount>> {
        let status = self.get_status().await.context("Failed to get status")?;

        let minimal_fee = status.minimal_fees;

        Ok(minimal_fee)
    }

    pub async fn get_absolute_expire_period(&mut self) -> Result<u64> {
        let status_response = self.get_status().await.context("Failed to get status")?;

        let last_slot = status_response.last_executed_speculative_slot;

        if let Some(last_slot) = last_slot {
            return Ok(last_slot.period + PERIOD_TO_LIVE_DEFAULT);
        }

        Err(Error::msg("Failed to get last executed speculative slot"))
    }

    pub async fn get_last_speculative_period(&mut self) -> Result<Option<u64>> {
        let status_response = self.get_status().await.context("Failed to get status")?;

        let last_slot = status_response.last_executed_speculative_slot;

        if let Some(last_slot) = last_slot {
            return Ok(Some(last_slot.period));
        }

        Ok(None)
    }

    pub async fn wait_for_operation(
        &mut self,
        operation_id: String,
        is_speculative: bool,
    ) -> Result<i32> {
        // Create an MPSC channel with a buffer size of 128.
        // This allows up to 128 messages to be buffered without blocking the sender.
        // If the receiver doesn't consume messages fast enough, sending will await (apply backpressure).
        // Adjust the buffer size based on expected message rate and latency tolerance.
        let (tx, rx) = mpsc::channel(128);

        // Create a ReceiverStream from the receiver end of the channel
        let ack = ReceiverStream::new(rx);

        // Create the request
        let request = Request::new(ack);

        // Send the request to the client
        let response = self
            .client
            .new_slot_execution_outputs(request)
            .await
            .context("Failed to send operations to the client")?;

        // Create the filter for the operation id
        let filter = NewSlotExecutionOutputsFilter {
            filter: Some(
                new_slot_execution_outputs_filter::Filter::ExecutedOpsChangesFilter(
                    ExecutedOpsChangesFilter {
                        filter: Some(executed_ops_changes_filter::Filter::OperationId(
                            operation_id.clone(),
                        )),
                    },
                ),
            ),
        };

        let filters = vec![filter];

        // Create the request stream for new slot execution outputs
        let request_stream = NewSlotExecutionOutputsRequest { filters };

        // Send the request stream using the channel
        tx.send(request_stream)
            .await
            .context("Failed to send operations using the channel")?;

        // Get the response stream
        let mut response_stream = response.into_inner();

        // Use the correct status based on the is_speculative flag
        let event_fetcher_condition_status = if is_speculative {
            ExecutionOutputStatus::Candidate as i32
        } else {
            ExecutionOutputStatus::Final as i32
        };

        // Loop through the response stream
        while let Some(response) = response_stream.next().await {
            let slot_execution_output = response
                .context("Failed to get message from send operations stream")?
                .output
                .context("Failed to get output from send operations response")?;

            if slot_execution_output.status == event_fetcher_condition_status {
                let execution_output = slot_execution_output.execution_output.context(
                    "Failed to get execution output from slot execution output response",
                )?;

                let states_changes = execution_output
                    .state_changes
                    .context("Failed to get states changes from execution output response")?;

                let executed_ops_changes = states_changes.executed_ops_changes;

                // Check if the operation id is in the executed_ops_changes vector and return its status
                for executed_ops_change in executed_ops_changes {
                    if executed_ops_change.operation_id == operation_id {
                        let operation_value = executed_ops_change
                            .value
                            .context("Failed to get operation value")?;

                        return Ok(operation_value.status);
                    }
                }
            }
        }

        Err(Error::msg(format!("Operation {} not found", operation_id)))
    }

    pub async fn get_operation_events(
        &mut self,
        operation_id: &str,
    ) -> Result<Vec<ScExecutionEvent>> {
        let filter = ScExecutionEventsFilter {
            filter: Some(sc_execution_events_filter::Filter::OriginalOperationId(
                operation_id.to_string(),
            )),
        };

        let request = Request::new(GetScExecutionEventsRequest {
            filters: vec![filter],
        });

        let response = self
            .client
            .get_sc_execution_events(request)
            .await
            .context("Failed to get sc execution events")?;

        let events = response.into_inner().events;

        Ok(events)
    }

    pub async fn get_mas_balance(&mut self, address: &str) -> Result<f64> {
        let request = Request::new(QueryStateRequest {
            queries: vec![ExecutionQueryRequestItem {
                request_item: Some(
                    execution_query_request_item::RequestItem::AddressBalanceCandidate(
                        AddressBalanceCandidate {
                            address: address.to_string(),
                        },
                    ),
                ),
            }],
        });

        let query_state_res = self
            .client
            .query_state(request)
            .await
            .context("Failed to query state")?
            .into_inner();
        let responses = query_state_res.responses;

        let balance_query_response = responses
            .get(0)
            .context("Failed to get query response")?
            .response
            .as_ref()
            .context("Failed to get query response")?;

        if let execution_query_response::Response::Result(query_response_item) =
            balance_query_response
        {
            if let Some(execution_query_response_item::ResponseItem::Amount(amount)) =
                &query_response_item.response_item
            {
                let formatted_amount = format_units(amount.mantissa, amount.scale as u8)
                    .unwrap_or_default()
                    .parse::<f64>()
                    .unwrap_or_default();

                return Ok(formatted_amount);
            }
        }

        Err(anyhow::anyhow!("Cannot get MAS balance"))
    }

    pub async fn get_operation_status(
        &mut self,
        operation_id: &str,
        is_final: bool,
    ) -> Result<i32> {
        let request_item = if is_final {
            execution_query_request_item::RequestItem::OpExecutionStatusFinal(
                OpExecutionStatusFinal {
                    operation_id: operation_id.to_string(),
                },
            )
        } else {
            execution_query_request_item::RequestItem::OpExecutionStatusCandidate(
                OpExecutionStatusCandidate {
                    operation_id: operation_id.to_string(),
                },
            )
        };

        let request = Request::new(QueryStateRequest {
            queries: vec![ExecutionQueryRequestItem {
                request_item: Some(request_item),
            }],
        });

        let response = self
            .client
            .query_state(request)
            .await
            .context("Failed to get the operation status")?
            .into_inner();

        if let Some(execution_query_response) = response.responses.first() {
            if let Some(op_exec_response) = &execution_query_response.response {
                if let execution_query_response::Response::Result(query_response_item) =
                    op_exec_response
                {
                    if let Some(execution_query_response_item::ResponseItem::ExecutionStatus(
                        status,
                    )) = &query_response_item.response_item
                    {
                        return Ok(*status);
                    }
                }
            }
        }

        Err(anyhow!("Failed to get the operation status"))
    }

    pub async fn get_storage_keys(
        &mut self,
        address: &str,
        prefix: Vec<u8>,
    ) -> Result<Vec<String>> {
        let query_state_request = QueryStateRequest {
            queries: vec![ExecutionQueryRequestItem {
                request_item: Some(
                    execution_query_request_item::RequestItem::AddressDatastoreKeysFinal(
                        AddressDatastoreKeysFinal {
                            address: address.to_string(),
                            prefix,
                            start_key: None,
                            inclusive_start_key: None,
                            end_key: None,
                            inclusive_end_key: None,
                            limit: None,
                        },
                    ),
                ),
            }],
        };

        let response = self
            .client
            .query_state(query_state_request)
            .await?
            .into_inner();

        if let Some(execution_query_response) = response.responses.first() {
            if let Some(storage_keys_response) = &execution_query_response.response {
                if let execution_query_response::Response::Result(query_response_item) =
                    storage_keys_response
                {
                    if let Some(execution_query_response_item::ResponseItem::VecBytes(
                        address_datastore_keys_final,
                    )) = &query_response_item.response_item
                    {
                        let storage_keys_bytes = &address_datastore_keys_final.items;

                        let mut storage_keys = Vec::new();

                        for storage_key_bytes in storage_keys_bytes {
                            let storage_key = bytes_to_string(storage_key_bytes);
                            storage_keys.push(storage_key);
                        }

                        return Ok(storage_keys);
                    }
                }
            }
        }

        Err(anyhow!("Failed to get the storage keys for the address"))
    }
}

#[cfg(test)]
mod tests {
    use massa_proto_rs::massa::model::v1::OperationExecutionStatus;

    use crate::{
        basic_elements::{args::Args, serializers::bytes_to_string},
        constants::MAX_GAS_CALL,
    };

    // Import the parent module
    use super::*;

    #[tokio::test]
    async fn test_get_status() {
        let mut client = PublicGrpcClient::new_buildnet().await.unwrap();
        let response = client.get_status().await.unwrap();

        // Assert response.status.version is "DEVN.28.12"
        assert_eq!(response.version, "DEVN.28.12");
    }

    #[tokio::test]
    async fn test_set_name() {
        let mut client = PublicGrpcClient::new_from_env()
            .await
            .expect("Failed to create client");

        let target_function = "setName";
        let fee = "0.1";
        // let max_gas = ((u32::MAX - 1) / 100) as u64;
        let max_gas = MAX_GAS_CALL;
        let target_address = "AS1KDFtTy8jaK31b36EtNfVCt6GLCYdRKQD3fS2J1B6vFJMSCTiW";
        let coins: f64 = 0.01;
        let expire_period = client
            .get_absolute_expire_period()
            .await
            .expect("Failed to get absolute expire period");

        let parameter = Args::new().add_string("Samir").serialize();

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

        // wait for the operation to complete speculative
        let operation_status = client
            .wait_for_operation(operation_id.clone(), true)
            .await
            .expect("Failed to wait for operation");

        println!("Operation status: {}", operation_status);

        // assert_eq!(operation_status, OperationExecutionStatus::Success as i32);

        let events = client
            .get_operation_events(&operation_id)
            .await
            .expect("Failed to get operations events");

        println!("Operation events: {:?}", &events);

        for event in events {
            let deserialized_data = bytes_to_string(&event.data);

            println!("Event Data: {:?}", &deserialized_data);

            let context = event.context.expect("Failed to get event context");

            println!("Event Context: {:?}", &context);
        }
    }

    #[tokio::test]
    async fn test_get_current_address() {
        let mut client = PublicGrpcClient::new_from_env()
            .await
            .expect("Failed to create client");

        let address = client.get_current_address().unwrap();

        let current_address = "AU12Yd4kCcsizeeTEK9AZyBnuJNZ1cpp99XfCZgzS77ZKnwTFMpVE";

        println!("Current address: {:?}", address);

        assert_eq!(address.to_string(), current_address);
    }

    #[tokio::test]
    async fn test_get_mas_balance() {
        let mut client = PublicGrpcClient::new_from_env()
            .await
            .expect("Failed to create client");

        let address = client.get_current_address().unwrap();

        let current_address = "AU12Yd4kCcsizeeTEK9AZyBnuJNZ1cpp99XfCZgzS77ZKnwTFMpVE";

        println!("Current address: {:?}", address);

        assert_eq!(address.to_string(), current_address);

        let balance = client.get_mas_balance(&address.to_string()).await.unwrap();

        println!("Current balance: {:?}", balance);
    }

    #[tokio::test]
    async fn test_get_storage_keys() {
        let mut client = PublicGrpcClient::new_from_env()
            .await
            .expect("Failed to create client");

        let address = "AS1fKChJfxdAVBUUSHya45cDrdfTXjPewjENszqeBbrW2tUS77QF";

        println!("Current address: {}", address);

        const BALANCE_PREFIX: u8 = 0x00;

        let prefix = vec![BALANCE_PREFIX];

        // let prefix = string_to_bytes("");

        let storage_keys = client
            .get_storage_keys(&address.to_string(), prefix)
            .await
            .unwrap();

        println!("Storage keys: {:?}", storage_keys);
    }
}
