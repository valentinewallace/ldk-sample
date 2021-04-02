use crate::byte_utils;
use bitcoin::secp256k1::{SecretKey, Secp256k1, All};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use lightning::chain::keysinterface::{InMemorySigner, StaticPaymentOutputDescriptor, DelayedPaymentOutputDescriptor};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use crate::keys::{SignerFactory, DynSigner, PaymentSign, InnerSign};
use bitcoin::Transaction;

// XXX This file helps main() put together the world with InMemorySigner

pub struct InMemorySignerFactory {
    seed: [u8; 32],
    secp_ctx: Secp256k1<All>,
}

impl InMemorySignerFactory {
    pub fn new(seed: &[u8; 32]) -> Self {
        InMemorySignerFactory {
            seed: seed.clone(),
            secp_ctx: Secp256k1::new(),
        }
    }
}

impl PaymentSign for InMemorySigner {
    fn sign_counterparty_payment_input_t(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Vec<Vec<u8>>, ()> {
        self.sign_counterparty_payment_input(spend_tx, input_idx, descriptor, secp_ctx)
    }

    fn sign_dynamic_p2wsh_input_t(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Vec<Vec<u8>>, ()> {
        self.sign_dynamic_p2wsh_input(spend_tx, input_idx, descriptor, secp_ctx)
    }
}

impl InnerSign for InMemorySigner {
    fn box_clone(&self) -> Box<dyn InnerSign + Sync> {
        Box::new(self.clone())
    }
}

impl SignerFactory for InMemorySignerFactory {
    fn derive_channel_keys(&self, channel_master_key: &ExtendedPrivKey, channel_value_satoshis: u64, params: &[u8; 32]) -> DynSigner {
        let chan_id = byte_utils::slice_to_be64(&params[0..8]);
        assert!(chan_id <= std::u32::MAX as u64); // Otherwise the params field wasn't created by us
        let mut unique_start = Sha256::engine();
        unique_start.input(params);
        unique_start.input(&self.seed);

        // We only seriously intend to rely on the channel_master_key for true secure
        // entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
        // starting_time provided in the constructor) to be unique.
        let child_privkey = channel_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(chan_id as u32).expect("key space exhausted")).expect("Your RNG is busted");
        unique_start.input(&child_privkey.private_key.key[..]);

        let seed = Sha256::from_engine(unique_start).into_inner();

        let commitment_seed = {
            let mut sha = Sha256::engine();
            sha.input(&seed);
            sha.input(&b"commitment seed"[..]);
            Sha256::from_engine(sha).into_inner()
        };
        macro_rules! key_step {
			($info: expr, $prev_key: expr) => {{
				let mut sha = Sha256::engine();
				sha.input(&seed);
				sha.input(&$prev_key[..]);
				sha.input(&$info[..]);
				SecretKey::from_slice(&Sha256::from_engine(sha).into_inner()).expect("SHA-256 is busted")
			}}
		}
        let funding_key = key_step!(b"funding key", commitment_seed);
        let revocation_base_key = key_step!(b"revocation base key", funding_key);
        let payment_key = key_step!(b"payment key", revocation_base_key);
        let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
        let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);

        let signer = InMemorySigner::new(
            &self.secp_ctx,
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_satoshis,
            params.clone()
        );

        DynSigner {
            inner: Box::new(signer)
        }
    }
}
