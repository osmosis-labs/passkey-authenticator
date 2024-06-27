// use anyhow::{Context, Result};
// use cosmwasm_schema::QueryResponses;
// use serde::{Deserialize, Serialize};
// const CONTRACT_ADDR: &str = "http://164.92.247.225:26657";
// const NODE_ID: &str = "osmo177xfj8lvtywmjxw0ep42cuyuz9fuym7nx3x6ldj5s37yjtn782hq5h8eed";



// use cosmwasm_schema::cw_serde;
// use cosmwasm_std::{to_json_binary, QueryRequest, WasmQuery};
// use schemars::JsonSchema;


// // use osmosis_std::
// // use cosmrs::rpc::cosmos::auth::v1beta1::query_client::QueryClient;

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct VerifySecp256r1SignatureQuery {
//     pub message: String,
//     pub signature: String,
//     pub public_key: String,
// }

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// pub struct VerifySecp256r1SignatureResponse {
//     pub verifies: bool,
// }

// #[cw_serde]
// #[derive(QueryResponses)]
// pub enum QueryMsg {
//     #[returns(VerifySecp256r1SignatureResponse)]
//     VerifySecp256r1Signature(VerifySecp256r1SignatureQuery),
// }

// #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
// enum NetworkVariant {
//     /// Beaker's state of the network will not be shared with collaborator via vcs
//     Local,

//     /// Beaker's state of the network will be shared with collaborator via vcs
//     Shared,
// }

// #[derive(Serialize, Deserialize, Clone, Debug)]
// struct Network {
//     /// Chain id used for defining which network you are operating on
//     chain_id: String,

//     /// Network variant used to specify whether state file of the network should be tracked in vcs or not
//     network_variant: NetworkVariant,

//     /// Endpoint for grpc
//     grpc_endpoint: String,

//     /// Endpoint for rpc
//     rpc_endpoint: String,
// }

// struct Client {
//     network: Network,
// }

// impl Client {
//     pub async fn query_smart(&self, address: String, query_data: Vec<u8>) -> Result<Vec<u8>> {
//         use cosmos_sdk_proto::cosmwasm::wasm::v1::*;
//         let grpc_endpoint = self.network.grpc_endpoint.clone();

//         let mut c = query_client::QueryClient::connect(self.network.grpc_endpoint.clone())
//             .await
//             .context(format!("Unable to connect to {grpc_endpoint}"))?;

//         let res = c
//             .smart_contract_state(QuerySmartContractStateRequest {
//                 address,
//                 query_data,
//             })
//             .await?
//             .into_inner()
//             .data;

//         Ok(res)
//     }
// }

// async fn test_verify_secp256r1_signature() {
//     const SECP256R1_MESSAGE_HEX: &str = "4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e";
//     const SECP256R1_SIGNATURE_HEX: &str = "1cc628533d0004b2b20e7f4baad0b8bb5e0673db159bbccf92491aef61fc9620880e0bbf82a8cf818ed46ba03cf0fc6c898e36fca36cc7fdb1d2db7503634430";
//     const SECP256R1_PUBLIC_KEY_HEX: &str = "04b8188bd68701fc396dab53125d4d28ea33a91daf6d21485f4770f6ea8c565dde423f058810f277f8fe076f6db56e9285a1bf2c2a1dae145095edd9c04970bc4a";

//     let query_msg = VerifySecp256r1SignatureQuery {
//         message: hex::encode(SECP256R1_MESSAGE_HEX),
//         signature: hex::encode(SECP256R1_SIGNATURE_HEX),
//         public_key: hex::encode(SECP256R1_PUBLIC_KEY_HEX),
//     };

//     let query_request = QueryRequest::Wasm(WasmQuery::Smart {
//         contract_addr: CONTRACT_ADDR.to_string(),
//         msg: to_json_binary(&QueryMsg::VerifySecp256r1Signature(query_msg)).unwrap(),
//     });

//     let response: VerifySecp256r1SignatureResponse = deps
//         .querier
//         .query(&query_request)
//         .await
//         .unwrap()
//         .try_into()
//         .unwrap();
// }
