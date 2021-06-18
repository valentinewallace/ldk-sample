use crate::disk;
use crate::hex_utils;
use crate::{
	ChannelManager, FilesystemLogger, HTLCStatus, MillisatAmount, PaymentInfo, PaymentInfoStorage,
	PeerManager,
};
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::PublicKey;
use lightning::chain;
use lightning::chain::keysinterface::KeysManager;
use lightning::ln::features::InvoiceFeatures;
use lightning::ln::msgs::NetAddress;
use lightning::ln::{PaymentHash, PaymentSecret};
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::routing::router;
use lightning::routing::router::RouteHint;
use lightning::util::config::{ChannelConfig, ChannelHandshakeLimits, UserConfig};
use lightning_invoice::{utils, Currency, Invoice};
use std::env;
use std::io;
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct LdkUserInfo {
	pub(crate) bitcoind_rpc_username: String,
	pub(crate) bitcoind_rpc_password: String,
	pub(crate) bitcoind_rpc_port: u16,
	pub(crate) bitcoind_rpc_host: String,
	pub(crate) ldk_storage_dir_path: String,
	pub(crate) ldk_peer_listening_port: u16,
	pub(crate) ldk_announced_listen_addr: Option<NetAddress>,
	pub(crate) ldk_announced_node_name: [u8; 32],
	pub(crate) network: Network,
}

pub(crate) fn parse_startup_args() -> Result<LdkUserInfo, ()> {
	if env::args().len() < 3 {
		println!("ldk-tutorial-node requires 3 arguments: `cargo run <bitcoind-rpc-username>:<bitcoind-rpc-password>@<bitcoind-rpc-host>:<bitcoind-rpc-port> ldk_storage_directory_path [<ldk-incoming-peer-listening-port>] [bitcoin-network] [announced-listen-addr announced-node-name]`");
		return Err(());
	}
	let bitcoind_rpc_info = env::args().skip(1).next().unwrap();
	let bitcoind_rpc_info_parts: Vec<&str> = bitcoind_rpc_info.split("@").collect();
	if bitcoind_rpc_info_parts.len() != 2 {
		println!("ERROR: bad bitcoind RPC URL provided");
		return Err(());
	}
	let rpc_user_and_password: Vec<&str> = bitcoind_rpc_info_parts[0].split(":").collect();
	if rpc_user_and_password.len() != 2 {
		println!("ERROR: bad bitcoind RPC username/password combo provided");
		return Err(());
	}
	let bitcoind_rpc_username = rpc_user_and_password[0].to_string();
	let bitcoind_rpc_password = rpc_user_and_password[1].to_string();
	let bitcoind_rpc_path: Vec<&str> = bitcoind_rpc_info_parts[1].split(":").collect();
	if bitcoind_rpc_path.len() != 2 {
		println!("ERROR: bad bitcoind RPC path provided");
		return Err(());
	}
	let bitcoind_rpc_host = bitcoind_rpc_path[0].to_string();
	let bitcoind_rpc_port = bitcoind_rpc_path[1].parse::<u16>().unwrap();

	let ldk_storage_dir_path = env::args().skip(2).next().unwrap();

	let mut ldk_peer_port_set = true;
	let ldk_peer_listening_port: u16 = match env::args().skip(3).next().map(|p| p.parse()) {
		Some(Ok(p)) => p,
		Some(Err(e)) => panic!("{}", e),
		None => {
			ldk_peer_port_set = false;
			9735
		}
	};

	let arg_idx = match ldk_peer_port_set {
		true => 4,
		false => 3,
	};
	let network: Network = match env::args().skip(arg_idx).next().as_ref().map(String::as_str) {
		Some("testnet") => Network::Testnet,
		Some("regtest") => Network::Regtest,
		Some(_) => panic!("Unsupported network provided. Options are: `regtest`, `testnet`"),
		None => Network::Testnet,
	};

	let ldk_announced_listen_addr = match env::args().skip(arg_idx + 1).next().as_ref() {
		Some(s) => match IpAddr::from_str(s) {
			Ok(IpAddr::V4(a)) => {
				Some(NetAddress::IPv4 { addr: a.octets(), port: ldk_peer_listening_port })
			}
			Ok(IpAddr::V6(a)) => {
				Some(NetAddress::IPv6 { addr: a.octets(), port: ldk_peer_listening_port })
			}
			Err(_) => panic!("Failed to parse announced-listen-addr into an IP address"),
		},
		None => None,
	};

	let ldk_announced_node_name = match env::args().skip(arg_idx + 2).next().as_ref() {
		Some(s) => {
			if s.len() > 32 {
				panic!("Node Alias can not be longer than 32 bytes");
			}
			let mut bytes = [0; 32];
			bytes[..s.len()].copy_from_slice(s.as_bytes());
			bytes
		}
		None => [0; 32],
	};

	Ok(LdkUserInfo {
		bitcoind_rpc_username,
		bitcoind_rpc_password,
		bitcoind_rpc_host,
		bitcoind_rpc_port,
		ldk_storage_dir_path,
		ldk_peer_listening_port,
		ldk_announced_listen_addr,
		ldk_announced_node_name,
		network,
	})
}

pub(crate) async fn poll_for_user_input(
	peer_manager: Arc<PeerManager>, channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>,
	router: Arc<NetGraphMsgHandler<Arc<dyn chain::Access + Send + Sync>, Arc<FilesystemLogger>>>,
	inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage,
	ldk_data_dir: String, logger: Arc<FilesystemLogger>, network: Network,
) {
	println!("LDK startup successful. To view available commands: \"help\".");
	println!("LDK logs are available at <your-supplied-ldk-data-dir-path>/.ldk/logs");
	println!("Local Node ID is {}.", channel_manager.get_our_node_id());
	let stdin = io::stdin();
	print!("> ");
	io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print
	for line in stdin.lock().lines() {
		let line = line.unwrap();
		let mut words = line.split_whitespace();
		if let Some(word) = words.next() {
			match word {
				"help" => help(),
				"openchannel" => {
					let peer_pubkey_and_ip_addr = words.next();
					let channel_value_sat = words.next();
					if peer_pubkey_and_ip_addr.is_none() || channel_value_sat.is_none() {
						println!("ERROR: openchannel has 2 required arguments: `openchannel pubkey@host:port channel_amt_satoshis` [--public]");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let peer_pubkey_and_ip_addr = peer_pubkey_and_ip_addr.unwrap();
					let (pubkey, peer_addr) =
						match parse_peer_info(peer_pubkey_and_ip_addr.to_string()) {
							Ok(info) => info,
							Err(e) => {
								println!("{:?}", e.into_inner().unwrap());
								print!("> ");
								io::stdout().flush().unwrap();
								continue;
							}
						};

					let chan_amt_sat: Result<u64, _> = channel_value_sat.unwrap().parse();
					if chan_amt_sat.is_err() {
						println!("ERROR: channel amount must be a number");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}

					if connect_peer_if_necessary(pubkey, peer_addr, peer_manager.clone())
						.await
						.is_err()
					{
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					};

					let announce_channel = match words.next() {
						Some("--public") | Some("--public=true") => true,
						Some("--public=false") => false,
						Some(_) => {
							println!("ERROR: invalid `--public` command format. Valid formats: `--public`, `--public=true` `--public=false`");
							print!("> ");
							io::stdout().flush().unwrap();
							continue;
						}
						None => false,
					};

					if open_channel(
						pubkey,
						chan_amt_sat.unwrap(),
						announce_channel,
						channel_manager.clone(),
					)
					.is_ok()
					{
						let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());
						let _ = disk::persist_channel_peer(
							Path::new(&peer_data_path),
							peer_pubkey_and_ip_addr,
						);
					}
				}
				"sendpayment" => {
					let invoice_str = words.next();
					if invoice_str.is_none() {
						println!("ERROR: sendpayment requires an invoice: `sendpayment <invoice>`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}

					let invoice = match Invoice::from_str(invoice_str.unwrap()) {
						Ok(inv) => inv,
						Err(e) => {
							println!("ERROR: invalid invoice: {:?}", e);
							print!("> ");
							io::stdout().flush().unwrap();
							continue;
						}
					};
					let last_hops = invoice.route_hints();

					let amt_pico_btc = invoice.amount_pico_btc();
					if amt_pico_btc.is_none() {
						println!("ERROR: invalid invoice: must contain amount to pay");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let amt_msat = amt_pico_btc.unwrap() / 10;

					let payee_pubkey = invoice.recover_payee_pub_key();
					let final_cltv = invoice.min_final_cltv_expiry() as u32;
					let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
					let payment_secret = invoice.payment_secret().cloned();
					let invoice_features = invoice.features().cloned();

					send_payment(
						payee_pubkey,
						amt_msat,
						final_cltv,
						payment_hash,
						payment_secret,
						invoice_features,
						last_hops,
						router.clone(),
						channel_manager.clone(),
						outbound_payments.clone(),
						logger.clone(),
					);
				}
          "keysend" => {
              let dest_pubkey = match words.next() {
                  Some(dest) => {
                      match hex_utils::to_compressed_pubkey(dest) {
                          Some(pk) => pk,
                          None => {
						                  println!("ERROR: couldn't parse destination pubkey");
						                  print!("> ");
						                  io::stdout().flush().unwrap();
						                  continue;
                          }
                      }
                  },
                  None => {
						          println!("ERROR: keysend requires a destination pubkey: `keysend <dest_pubkey> <amt_msat>`");
						          print!("> ");
						          io::stdout().flush().unwrap();
						          continue;
                  }
              };
              let amt_msat_str = match words.next() {
                  Some(amt) => amt,
                  None => {
						          println!("ERROR: keysend requires an amount in millisatoshis: `keysend <dest_pubkey> <amt_msat>`");

						          print!("> ");
						          io::stdout().flush().unwrap();
						          continue;
                  }
              };
              let amt_msat: u64 = match amt_msat_str.parse() {
                  Ok(amt) => amt,
                  Err(e) => {
                      println!("ERROR: couldn't parse amount_msat: {}", e);
						          print!("> ");
						          io::stdout().flush().unwrap();
						          continue;
                  }
              };
              keysend(dest_pubkey, amt_msat, router.clone(), channel_manager.clone(), outbound_payments.clone(), logger.clone());
          }
				"getinvoice" => {
					let amt_str = words.next();
					if amt_str.is_none() {
						println!("ERROR: getinvoice requires an amount in millisatoshis");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}

					let amt_msat: Result<u64, _> = amt_str.unwrap().parse();
					if amt_msat.is_err() {
						println!("ERROR: getinvoice provided payment amount was not a number");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					get_invoice(
						amt_msat.unwrap(),
						inbound_payments.clone(),
						channel_manager.clone(),
						keys_manager.clone(),
						network,
					);
				}
				"connectpeer" => {
					let peer_pubkey_and_ip_addr = words.next();
					if peer_pubkey_and_ip_addr.is_none() {
						println!("ERROR: connectpeer requires peer connection info: `connectpeer pubkey@host:port`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let (pubkey, peer_addr) =
						match parse_peer_info(peer_pubkey_and_ip_addr.unwrap().to_string()) {
							Ok(info) => info,
							Err(e) => {
								println!("{:?}", e.into_inner().unwrap());
								print!("> ");
								io::stdout().flush().unwrap();
								continue;
							}
						};
					if connect_peer_if_necessary(pubkey, peer_addr, peer_manager.clone())
						.await
						.is_ok()
					{
						println!("SUCCESS: connected to peer {}", pubkey);
					}
				}
				"listchannels" => list_channels(channel_manager.clone()),
				"listpayments" => {
					list_payments(inbound_payments.clone(), outbound_payments.clone())
				}
				"closechannel" => {
					let channel_id_str = words.next();
					if channel_id_str.is_none() {
						println!("ERROR: closechannel requires a channel ID: `closechannel <channel_id>`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
					if channel_id_vec.is_none() {
						println!("ERROR: couldn't parse channel_id as hex");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let mut channel_id = [0; 32];
					channel_id.copy_from_slice(&channel_id_vec.unwrap());
					close_channel(channel_id, channel_manager.clone());
				}
				"forceclosechannel" => {
					let channel_id_str = words.next();
					if channel_id_str.is_none() {
						println!("ERROR: forceclosechannel requires a channel ID: `forceclosechannel <channel_id>`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
					if channel_id_vec.is_none() {
						println!("ERROR: couldn't parse channel_id as hex");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let mut channel_id = [0; 32];
					channel_id.copy_from_slice(&channel_id_vec.unwrap());
					force_close_channel(channel_id, channel_manager.clone());
				}
				"nodeinfo" => node_info(channel_manager.clone(), peer_manager.clone()),
				"listpeers" => list_peers(peer_manager.clone()),
				_ => println!("Unknown command. See `\"help\" for available commands."),
			}
		}
		print!("> ");
		io::stdout().flush().unwrap();
	}
}

fn help() {
	println!("openchannel pubkey@host:port <amt_satoshis>");
	println!("sendpayment <invoice>");
	println!("getinvoice <amt_millisatoshis>");
	println!("connectpeer pubkey@host:port");
	println!("listchannels");
	println!("listpayments");
	println!("closechannel <channel_id>");
	println!("forceclosechannel <channel_id>");
	println!("nodeinfo");
	println!("listpeers");
}

fn node_info(channel_manager: Arc<ChannelManager>, peer_manager: Arc<PeerManager>) {
	println!("\t{{");
	println!("\t\t node_pubkey: {}", channel_manager.get_our_node_id());
	println!("\t\t num_channels: {}", channel_manager.list_channels().len());
	println!("\t\t num_usable_channels: {}", channel_manager.list_usable_channels().len());
	println!("\t\t num_peers: {}", peer_manager.get_peer_node_ids().len());
	println!("\t}},");
}

fn list_peers(peer_manager: Arc<PeerManager>) {
	println!("\t{{");
	for pubkey in peer_manager.get_peer_node_ids() {
		println!("\t\t pubkey: {}", pubkey);
	}
	println!("\t}},");
}

fn list_channels(channel_manager: Arc<ChannelManager>) {
	print!("[");
	for chan_info in channel_manager.list_channels() {
		println!("");
		println!("\t{{");
		println!("\t\tchannel_id: {},", hex_utils::hex_str(&chan_info.channel_id[..]));
		if let Some(funding_txo) = chan_info.funding_txo {
			println!("\t\tfunding_txid: {},", funding_txo.txid);
		}
		println!(
			"\t\tpeer_pubkey: {},",
			hex_utils::hex_str(&chan_info.remote_network_id.serialize())
		);
		if let Some(id) = chan_info.short_channel_id {
			println!("\t\tshort_channel_id: {},", id);
		}
		println!("\t\tis_confirmed_onchain: {},", chan_info.is_funding_locked);
		println!("\t\tchannel_value_satoshis: {},", chan_info.channel_value_satoshis);
		if chan_info.is_usable {
			println!("\t\tavailable_balance_for_send_msat: {},", chan_info.outbound_capacity_msat);
			println!("\t\tavailable_balance_for_recv_msat: {},", chan_info.inbound_capacity_msat);
		}
		println!("\t\tchannel_can_send_payments: {},", chan_info.is_usable);
		println!("\t\tpublic: {},", chan_info.is_public);
		println!("\t}},");
	}
	println!("]");
}

fn list_payments(inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage) {
	let inbound = inbound_payments.lock().unwrap();
	let outbound = outbound_payments.lock().unwrap();
	print!("[");
	for (payment_hash, payment_info) in inbound.deref() {
		println!("");
		println!("\t{{");
		println!("\t\tamount_millisatoshis: {},", payment_info.amt_msat);
		println!("\t\tpayment_hash: {},", hex_utils::hex_str(&payment_hash.0));
		println!("\t\thtlc_direction: inbound,");
		println!(
			"\t\thtlc_status: {},",
			match payment_info.status {
				HTLCStatus::Pending => "pending",
				HTLCStatus::Succeeded => "succeeded",
				HTLCStatus::Failed => "failed",
			}
		);

		println!("\t}},");
	}

	for (payment_hash, payment_info) in outbound.deref() {
		println!("");
		println!("\t{{");
		println!("\t\tamount_millisatoshis: {},", payment_info.amt_msat);
		println!("\t\tpayment_hash: {},", hex_utils::hex_str(&payment_hash.0));
		println!("\t\thtlc_direction: outbound,");
		println!(
			"\t\thtlc_status: {},",
			match payment_info.status {
				HTLCStatus::Pending => "pending",
				HTLCStatus::Succeeded => "succeeded",
				HTLCStatus::Failed => "failed",
			}
		);

		println!("\t}},");
	}
	println!("]");
}

pub(crate) async fn connect_peer_if_necessary(
	pubkey: PublicKey, peer_addr: SocketAddr, peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
	for node_pubkey in peer_manager.get_peer_node_ids() {
		if node_pubkey == pubkey {
			return Ok(());
		}
	}
	match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
	{
		Some(connection_closed_future) => {
			let mut connection_closed_future = Box::pin(connection_closed_future);
			loop {
				match futures::poll!(&mut connection_closed_future) {
					std::task::Poll::Ready(_) => {
						println!("ERROR: Peer disconnected before we finished the handshake");
						return Err(());
					}
					std::task::Poll::Pending => {}
				}
				// Avoid blocking the tokio context by sleeping a bit
				match peer_manager.get_peer_node_ids().iter().find(|id| **id == pubkey) {
					Some(_) => break,
					None => tokio::time::sleep(Duration::from_millis(10)).await,
				}
			}
		}
		None => {
			println!("ERROR: failed to connect to peer");
			return Err(());
		}
	}
	Ok(())
}

fn open_channel(
	peer_pubkey: PublicKey, channel_amt_sat: u64, announced_channel: bool,
	channel_manager: Arc<ChannelManager>,
) -> Result<(), ()> {
	let config = UserConfig {
		peer_channel_config_limits: ChannelHandshakeLimits {
			// lnd's max to_self_delay is 2016, so we want to be compatible.
			their_to_self_delay: 2016,
			..Default::default()
		},
		channel_options: ChannelConfig { announced_channel, ..Default::default() },
		..Default::default()
	};

	match channel_manager.create_channel(peer_pubkey, channel_amt_sat, 0, 0, Some(config)) {
		Ok(_) => {
			println!("EVENT: initiated channel with peer {}. ", peer_pubkey);
			return Ok(());
		}
		Err(e) => {
			println!("ERROR: failed to open channel: {:?}", e);
			return Err(());
		}
	}
}

fn send_payment(
	payee: PublicKey, amt_msat: u64, final_cltv: u32, payment_hash: PaymentHash,
	payment_secret: Option<PaymentSecret>, payee_features: Option<InvoiceFeatures>,
	route_hints: Vec<&RouteHint>,
	router: Arc<NetGraphMsgHandler<Arc<dyn chain::Access + Send + Sync>, Arc<FilesystemLogger>>>,
	channel_manager: Arc<ChannelManager>, payment_storage: PaymentInfoStorage,
	logger: Arc<FilesystemLogger>,
) {
	let network_graph = router.network_graph.read().unwrap();
	let first_hops = channel_manager.list_usable_channels();
	let payer_pubkey = channel_manager.get_our_node_id();

	let route = router::get_route(
		&payer_pubkey,
		&network_graph,
		&payee,
		payee_features,
		Some(&first_hops.iter().collect::<Vec<_>>()),
		&route_hints,
		amt_msat,
		final_cltv,
		logger,
	);
	if let Err(e) = route {
		println!("ERROR: failed to find route: {}", e.err);
		return;
	}
	let status = match channel_manager.send_payment(&route.unwrap(), payment_hash, &payment_secret)
	{
		Ok(()) => {
			println!("EVENT: initiated sending {} msats to {}", amt_msat, payee);
			HTLCStatus::Pending
		}
		Err(e) => {
			println!("ERROR: failed to send payment: {:?}", e);
			HTLCStatus::Failed
		}
	};
	let mut payments = payment_storage.lock().unwrap();
	payments.insert(
		payment_hash,
		PaymentInfo {
			preimage: None,
			secret: payment_secret,
			status,
			amt_msat: MillisatAmount(Some(amt_msat)),
		},
	);
}

fn keysend(payee: PublicKey, amt_msat: u64, router: Arc<NetGraphMsgHandler<Arc<dyn chain::Access + Send + Sync>, Arc<FilesystemLogger>>>, channel_manager: Arc<ChannelManager>, payment_storage: PaymentInfoStorage, logger: Arc<FilesystemLogger>) {
	  let network_graph = router.network_graph.read().unwrap();
	  let first_hops = channel_manager.list_usable_channels();
	  let payer_pubkey = channel_manager.get_our_node_id();

    println!("VMW: in keysend");
	  let route = match router::get_route(
		    &payer_pubkey,
		    &network_graph,
		    &payee,
		    None,
		    Some(&first_hops.iter().collect::<Vec<_>>()),
		    &vec![],
		    amt_msat,
		    40,
		    logger,
	  ) {
        Ok(r) => r,
        Err(e) => {
		        println!("ERROR: failed to find route: {}", e.err);
		        return;
        }
    };

    println!("VMW: got route");
    channel_manager.keysend(&route).unwrap();
    println!("VMW: keysend'd");
}

fn get_invoice(
	amt_msat: u64, payment_storage: PaymentInfoStorage, channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>, network: Network,
) {
	let mut payments = payment_storage.lock().unwrap();
	let currency = match network {
		Network::Bitcoin => Currency::Bitcoin,
		Network::Testnet => Currency::BitcoinTestnet,
		Network::Regtest => Currency::Regtest,
		Network::Signet => panic!("Signet unsupported"),
	};
	let invoice = match utils::create_invoice_from_channelmanager(
		&channel_manager,
		keys_manager,
		currency,
		Some(amt_msat),
		"ldk-tutorial-node".to_string(),
	) {
		Ok(inv) => {
			println!("SUCCESS: generated invoice: {}", inv);
			inv
		}
		Err(e) => {
			println!("ERROR: failed to create invoice: {:?}", e);
			return;
		}
	};

	let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
	payments.insert(
		payment_hash,
		PaymentInfo {
			preimage: None,
			secret: invoice.payment_secret().cloned(),
			status: HTLCStatus::Pending,
			amt_msat: MillisatAmount(Some(amt_msat)),
		},
	);
}

fn close_channel(channel_id: [u8; 32], channel_manager: Arc<ChannelManager>) {
	match channel_manager.close_channel(&channel_id) {
		Ok(()) => println!("EVENT: initiating channel close"),
		Err(e) => println!("ERROR: failed to close channel: {:?}", e),
	}
}

fn force_close_channel(channel_id: [u8; 32], channel_manager: Arc<ChannelManager>) {
	match channel_manager.force_close_channel(&channel_id) {
		Ok(()) => println!("EVENT: initiating channel force-close"),
		Err(e) => println!("ERROR: failed to force-close channel: {:?}", e),
	}
}

pub(crate) fn parse_peer_info(
	peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), std::io::Error> {
	let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split("@");
	let pubkey = pubkey_and_addr.next();
	let peer_addr_str = pubkey_and_addr.next();
	if peer_addr_str.is_none() || peer_addr_str.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
		));
	}

	let peer_addr = peer_addr_str.unwrap().to_socket_addrs().map(|mut r| r.next());
	if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: couldn't parse pubkey@host:port into a socket address",
		));
	}

	let pubkey = hex_utils::to_compressed_pubkey(pubkey.unwrap());
	if pubkey.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: unable to parse given pubkey for node",
		));
	}

	Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}
