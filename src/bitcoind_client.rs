use crate::convert::{BlockchainInfo, FeeResponse, FundedTx, NewAddress, RawTx, SignedTx};
use base64;
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::hash_types::BlockHash;
use bitcoin::util::address::Address;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::http::HttpEndpoint;
use lightning_block_sync::rpc::RpcClient;
use lightning_block_sync::{AsyncBlockSourceResult, BlockHeaderData, BlockSource};
use serde_json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub struct BitcoindClient {
	// bitcoind_rpc_client: RpcClient,
	bitcoind_rpc_client: Mutex<RpcClient>,
	host: String,
	port: u16,
	rpc_user: String,
	rpc_password: String,
	fees: Arc<HashMap<String, u32>>,
}

impl BlockSource for &BitcoindClient {
	fn get_header<'a>(
		&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		  let mut rpc = self.bitcoind_rpc_client.lock().unwrap();
		// self.bitcoind_rpc_client.get_header(header_hash, height_hint)
		rpc.get_header(header_hash, height_hint)
	}
	fn get_block<'a>(
		&'a mut self, header_hash: &'a BlockHash,
	) -> AsyncBlockSourceResult<'a, Block> {
		  // self.bitcoind_rpc_client.get_block(header_hash)
		  let mut rpc = self.bitcoind_rpc_client.lock().unwrap();
		rpc.get_block(header_hash)
	}
	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
		// self.bitcoind_rpc_client.get_best_block()
		  let mut rpc = self.bitcoind_rpc_client.lock().unwrap();
		rpc.get_best_block()
	}
}

impl BitcoindClient {
	pub fn new(
		host: String, port: u16, rpc_user: String, rpc_password: String,
	) -> std::io::Result<Self> {
		let http_endpoint = HttpEndpoint::for_host(host.clone()).with_port(port);
		let rpc_credentials =
			base64::encode(format!("{}:{}", rpc_user.clone(), rpc_password.clone()));
		let bitcoind_rpc_client = RpcClient::new(&rpc_credentials, http_endpoint)?;
		let client = Self {
			// bitcoind_rpc_client,
			bitcoind_rpc_client: Mutex::new(bitcoind_rpc_client),
			host,
			port,
			rpc_user,
			rpc_password,
			fees: Arc::new(HashMap::new()),
		};
		client.poll_for_fee_estimates();
		Ok(client)
	}

	fn poll_for_fee_estimates(&self) {
		let bitcoind_rpc_client = self.get_new_rpc_client().unwrap();
		let mut rpc = self.get_new_rpc_client().unwrap();
		let mut fees = self.fees.clone();
		tokio::spawn(async {
			loop {
				let background_conf_target = serde_json::json!(144);
				let background_estimate_mode = serde_json::json!("ECONOMICAL");

				let background_estimate = bitcoind_rpc_client
					.call_method::<FeeResponse>(
						"estimatesmartfee",
						&vec![background_conf_target, background_estimate_mode],
					)
					.await
					.unwrap();
				match background_estimate.feerate {
					Some(fee) => fees.insert("background".to_string(), fee),
					None => fees.insert("background".to_string(), 253),
				};
				// fees.insert("background".to_string(), background_estimate);
			}
		});
	}

	pub fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
		let http_endpoint = HttpEndpoint::for_host(self.host.clone()).with_port(self.port);
		let rpc_credentials =
			base64::encode(format!("{}:{}", self.rpc_user.clone(), self.rpc_password.clone()));
		RpcClient::new(&rpc_credentials, http_endpoint)
	}

	// pub async fn create_raw_transaction(&mut self, outputs: Vec<HashMap<String, f64>>) -> RawTx {
	pub async fn create_raw_transaction(&self, outputs: Vec<HashMap<String, f64>>) -> RawTx {
		let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		let outputs_json = serde_json::json!(outputs);
		// self.bitcoind_rpc_client
		rpc.call_method::<RawTx>("createrawtransaction", &vec![serde_json::json!([]), outputs_json])
			.await
			.unwrap()
	}

	// pub async fn fund_raw_transaction(&mut self, raw_tx: RawTx) -> FundedTx {
	pub async fn fund_raw_transaction(&self, raw_tx: RawTx) -> FundedTx {
		let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		let raw_tx_json = serde_json::json!(raw_tx.0);
		// self.bitcoind_rpc_client.call_method("fundrawtransaction", &[raw_tx_json]).await.unwrap()
		rpc.call_method("fundrawtransaction", &[raw_tx_json]).await.unwrap()
	}

	// pub async fn sign_raw_transaction_with_wallet(&mut self, tx_hex: String) -> SignedTx {
	pub async fn sign_raw_transaction_with_wallet(&self, tx_hex: String) -> SignedTx {
		let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		let tx_hex_json = serde_json::json!(tx_hex);
		// self.bitcoind_rpc_client
		rpc.call_method("signrawtransactionwithwallet", &vec![tx_hex_json]).await.unwrap()
	}

	// pub async fn get_new_address(&mut self) -> Address {
	pub async fn get_new_address(&self) -> Address {
		let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		let addr_args = vec![serde_json::json!("LDK output address")];
		// let addr = self
		// 	.bitcoind_rpc_client
		let addr = rpc.call_method::<NewAddress>("getnewaddress", &addr_args).await.unwrap();
		Address::from_str(addr.0.as_str()).unwrap()
	}

	// pub async fn get_blockchain_info(&mut self) -> BlockchainInfo {
	pub async fn get_blockchain_info(&self) -> BlockchainInfo {
		let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		// self.bitcoind_rpc_client
		rpc.call_method::<BlockchainInfo>("getblockchaininfo", &vec![]).await.unwrap()
	}
}

impl FeeEstimator for BitcoindClient {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
		253
		// let mut rpc = self.bitcoind_rpc_client.lock().unwrap();

		// let (conf_target, estimate_mode, default) = match confirmation_target {
		// 	ConfirmationTarget::Background => (144, "ECONOMICAL", 253),
		// 	ConfirmationTarget::Normal => (18, "ECONOMICAL", 20000),
		// 	ConfirmationTarget::HighPriority => (6, "CONSERVATIVE", 50000),
		// };

		// // This function may be called from a tokio runtime, or not. So we need to check before
		// // making the call to avoid the error "cannot run a tokio runtime from within a tokio runtime".
		// let conf_target_json = serde_json::json!(conf_target);
		// let estimate_mode_json = serde_json::json!(estimate_mode);
		// let resp = match Handle::try_current() {
		// 	Ok(_) => tokio::task::block_in_place(|| {
		// 		runtime
		// 			.block_on(rpc.call_method::<FeeResponse>(
		// 				"estimatesmartfee",
		// 				&vec![conf_target_json, estimate_mode_json],
		// 			))
		// 			.unwrap()
		// 	}),
		// 	_ => runtime
		// 		.block_on(rpc.call_method::<FeeResponse>(
		// 			"estimatesmartfee",
		// 			&vec![conf_target_json, estimate_mode_json],
		// 		))
		// 		.unwrap(),
		// };
		// if resp.errored {
		// 	return default;
		// }
		// resp.feerate.unwrap()
	}
}

impl BroadcasterInterface for BitcoindClient {
	fn broadcast_transaction(&self, tx: &Transaction) {
		// let mut rpc = self.bitcoind_rpc_client.lock().unwrap();
		// let runtime = self.runtime.lock().unwrap();

		// let tx_serialized = serde_json::json!(encode::serialize_hex(tx));
		// // This function may be called from a tokio runtime, or not. So we need to check before
		// // making the call to avoid the error "cannot run a tokio runtime from within a tokio runtime".
		// match Handle::try_current() {
		// 	Ok(_) => {
		// 		tokio::task::block_in_place(|| {
		// 			runtime
		// 				.block_on(
		// 					rpc.call_method::<RawTx>("sendrawtransaction", &vec![tx_serialized]),
		// 				)
		// 				.unwrap();
		// 		});
		// 	}
		// 	_ => {
		// 		runtime
		// 			.block_on(rpc.call_method::<RawTx>("sendrawtransaction", &vec![tx_serialized]))
		// 			.unwrap();
		// 	}
		// }
	}
}
