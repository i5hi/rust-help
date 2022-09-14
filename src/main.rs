use serde_derive::{Deserialize, Serialize};
use std::str::{FromStr};
use secp256k1::Secp256k1;
use secp256k1::{ecdh::SharedSecret, KeyPair, PublicKey, SecretKey};
use bip39::{Language, Mnemonic};
use bitcoin::network::constants::Network;
use secp256k1::rand::rngs::OsRng;
use bitcoin::util::bip32::ExtendedPrivKey;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeySeed {
  pub fingerprint: String,
  pub mnemonic: String,
  pub xprv: String,
}

pub fn generate(
    length: usize, 
    passphrase: &str, 
    network: Network
  ) -> MasterKeySeed {
    let secp = Secp256k1::new();
    let length: usize = if length == 12 || length == 24 {
      length
    } else {
      24
    };
    let mut rng =  OsRng::new().unwrap();
    let mnemonic =  Mnemonic::generate_in_with(&mut rng, Language::English, length).unwrap();
    let mnemonic_struct =  Mnemonic::parse_in(Language::English, &mnemonic.to_string()).unwrap();
    let seed = mnemonic_struct.to_seed(passphrase);
    let master_xprv =  ExtendedPrivKey::new_master(network, &seed).unwrap();

    MasterKeySeed {
      fingerprint: master_xprv.fingerprint(&secp).to_string(),
      mnemonic: mnemonic.to_string(),
      xprv: master_xprv.to_string(),
    }
  }


#[derive(Serialize, Deserialize, Debug)]
pub struct XOnlyPair {
  pub seckey: String,
  pub pubkey: String,
}
impl XOnlyPair {
  pub fn from_keypair(keypair: KeyPair) -> XOnlyPair {
    return XOnlyPair {
      seckey: hex::encode(keypair.secret_bytes()).to_string(),
      pubkey: keypair.public_key().to_string(), // creates an XOnlyPubKey
    };
  }
}

pub fn keypair_from_xprv_str(xprv: &str) -> KeyPair {
  let secp = Secp256k1::new();
  let xprv =  ExtendedPrivKey::from_str(xprv).unwrap();
  let key_pair = KeyPair::from_seckey_str(&secp, &hex::encode(xprv.private_key.secret_bytes())).unwrap();
  key_pair
}

pub fn keypair_from_seckey_str(seckey: &str) -> KeyPair {
  let secp = Secp256k1::new();
  let key_pair = KeyPair::from_seckey_str(&secp, seckey).unwrap();
  key_pair
}

/// Generate a ecdsa shared secret
pub fn compute_shared_secret_str(
  seckey: &str, 
  pubkey: &str
) -> String {
  let secret_key = SecretKey::from_str(seckey).unwrap();

  let public_key = if pubkey.clone().len() == 64 {
    "02".to_string() + pubkey.clone()
  } else if pubkey.clone().len() == 66 {
    pubkey.to_string()
  } else {
     panic!("STOP IT!")
  };

  let pubkey = PublicKey::from_str(&public_key).unwrap();

  let shared_secret = SharedSecret::new(&pubkey, &secret_key);
  let shared_secret_hex = hex::encode(&(shared_secret.secret_bytes()));
  shared_secret_hex
}

#[cfg(test)]
mod tests {
  use super::*;
  use bitcoin::network::constants::Network;

  #[test]
  fn test_shared_secret() {
    let seed = generate(24, "", Network::Bitcoin);
    let key_pair = keypair_from_xprv_str(&seed.xprv);
    let alice_pair = XOnlyPair::from_keypair(key_pair);

    let seed = generate(24, "", Network::Bitcoin);
    let key_pair = keypair_from_xprv_str(&seed.xprv);
    let bob_pair = XOnlyPair::from_keypair(key_pair);
    
    // Alice only has Bob's XOnlyPubkey string
    let alice_shared_secret =
      compute_shared_secret_str(&alice_pair.seckey, &bob_pair.pubkey);

    // Bob only has Alice's XOnlyPubkey string
    let bob_shared_secret =
      compute_shared_secret_str(&bob_pair.seckey, &alice_pair.pubkey);
    assert_eq!(alice_shared_secret, bob_shared_secret);
  }
}

fn main() {
    println!("Help!");
}
