mod errors;
mod keys;
mod tags;

use bitcoin::{key::Secp256k1, secp256k1::All};
pub use errors::*;

pub struct MuSig2<'a> {
    secp: &'a Secp256k1<All>,
}

impl<'a> MuSig2<'a> {
    pub fn new(secp: &'a Secp256k1<All>) -> Self {
        Self { secp }
    }
}
