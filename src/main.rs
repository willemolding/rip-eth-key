use std::str::FromStr;
use std::io::Read;
use std::path::PathBuf;
use structopt::StructOpt;
use sliding_windows::{IterExt, Storage};
use secp256k1::key::{SecretKey, PublicKey};

#[derive(Debug, StructOpt)]
#[structopt(name = "rip-eth-key", about = "Searches a binary for the private key corresponding to an ethereum public key")]
struct Opt {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    #[structopt()]
    target_key: String
}

fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    let f = std::fs::File::open(opt.input)?;

    let target_key = PublicKey::from_str(&opt.target_key).unwrap();

    if let Some(key) = scan_for_key(f, target_key) {
        println!("found key: {}", key);
    } else {
        println!("key not found")
    }

    Ok(())
}

fn scan_for_key<T>(rdr: T, target_key: PublicKey) -> Option<SecretKey> 
    where T: Read
{
    let context = secp256k1::Secp256k1::new();

    // iterate over the sliding windows, convert them to a public key and then check if it matches the known one
    let mut storage: Storage<u8> = Storage::new(32);
    rdr.bytes().map(|b|b.unwrap()).sliding_windows(&mut storage).find_map(|window| {
        let bytes: Vec<u8> = window.into_iter().cloned().collect();

        if let Ok(secret_key) = SecretKey::from_slice(&bytes) {
            let public_key = PublicKey::from_secret_key(&context, &secret_key);

            if public_key == target_key {
                Some(secret_key)
            } else {
                None
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_planted_key() {
        unimplemented!();
    }
}
