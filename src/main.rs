use anyhow::{bail, Result};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use bdk::bitcoin::Network;
use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;
use std::io;

fn main() -> Result<()> {
    let mut input = String::new();

    println!("Please enter your BIP39 mnemonic seed phrase:");

    if let Err(e) = io::stdin().read_line(&mut input) {
        bail!("Failed to read mnemonic seed phrase: {e:?}");
    }

    let mnemonic = Mnemonic::parse(input)?;

    // This is how we derive the on-chain wallet seed in 10101.
    let mut ext_priv_key_seed = [0u8; 64];
    Hkdf::<Sha256>::new(None, &mnemonic.to_seed_normalized(""))
        .expand(b"BITCOIN_WALLET_SEED", &mut ext_priv_key_seed)
        .expect("array is of correct length");

    let key = ExtendedPrivKey::new_master(Network::Bitcoin, &ext_priv_key_seed)?;

    println!("BIP32 master private key:");
    println!("{key}");

    Ok(())
}
