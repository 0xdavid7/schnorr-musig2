// // NonceGenOption is a function option that allows callers to modify how nonce
// // generation happens.
// type NonceGenOption func(*nonceGenOpts)

// // nonceGenOpts is the set of options that control how nonce generation
// // happens.
// type nonceGenOpts struct {
// 	// randReader is what we'll use to generate a set of random bytes. If
// 	// unspecified, then the normal crypto/rand rand.Read method will be
// 	// used in place.
// 	randReader io.Reader

// 	// publicKey is the mandatory public key that will be mixed into the nonce
// 	// generation.
// 	publicKey []byte

// 	// secretKey is an optional argument that's used to further augment the
// 	// generated nonce by xor'ing it with this secret key.
// 	secretKey []byte

// 	// combinedKey is an optional argument that if specified, will be
// 	// combined along with the nonce generation.
// 	combinedKey []byte

// 	// msg is an optional argument that will be mixed into the nonce
// 	// derivation algorithm.
// 	msg []byte

// 	// auxInput is an optional argument that will be mixed into the nonce
// 	// derivation algorithm.
// 	auxInput []byte
// }

use bitcoin::secp256k1::{self, PublicKey};
use rand::{rngs::OsRng, TryRngCore};
use std::io::{self, Write};

use crate::{
    errors::{MuSig2Error, MuSig2Result},
    MuSig2, N_BYTES,
};

type NonceGenOpptionModifer = Box<dyn Fn(&mut NonceGenOpption)>;
type ByteOrder = String;
// Trait alias for the length writer function
type LengthWriter = fn(&mut dyn Write, &[u8]) -> io::Result<()>;

pub struct NonceGenOpption {
    pub rand: Box<OsRng>, // TODO: Allow customing rand
    pub public_key: secp256k1::PublicKey,
    pub secret_key: Option<secp256k1::SecretKey>,
    pub combined_key: Option<Vec<u8>>,
    pub msg: Option<[u8; N_BYTES]>,
    pub aux_input: Option<Vec<u8>>,
}

impl NonceGenOpption {
    pub fn with_nonce_secret_key_aux(key: secp256k1::SecretKey) -> impl Fn(&mut NonceGenOpption) {
        move |o| o.secret_key = Some(key)
    }

    // TODO: add more options
    pub fn apply(&mut self, modifiers: &[NonceGenOpptionModifer]) {
        for modifier in modifiers {
            modifier(self);
        }
    }
}

impl MuSig2<'_> {
    pub fn gen_nonces(
        key: secp256k1::PublicKey,
        modifiers: Option<&[NonceGenOpptionModifer]>,
    ) -> MuSig2Result<()> {
        // let mut opts = NonceGenOpption {
        //     rand: Box::new(OsRng),
        //     public_key: key,
        //     secret_key: None,
        //     combined_key: None,
        //     msg: None,
        //     aux_input: None,
        // };

        // if let Some(m) = modifiers {
        //     opts.apply(m);
        // };

        // let mut rand_bytes = [0u8; N_BYTES];
        // opts.rand.try_fill_bytes(&mut rand_bytes).unwrap();

        // if opts.secret_key.is_some() {
        //     // TODO: support secret key
        //     return Err(MuSig2Error::Other(anyhow::anyhow!(
        //         "Currently not supported"
        //     )));
        // }

        // let k1 = gen_nonce_aux_bytes(&rand_bytes, public_key, 0, &opts)?;

        Ok(())
    }

    // fn gen_nonce_aux_bytes(
    //     rand: &[u8; N_BYTES],
    //     pubkey: &PublicKey,
    //     i: u8,
    //     opts: &NonceGenOpption,
    // ) -> MuSig2Result<[u8; N_BYTES]> {
    //     let mut buf = Vec::new();

    //     buf.extend_from_slice(rand);

    //     Self::write_bytes_prefix(&mut buf, pubkey, uint8_writer)?;

    //     if let Some(combined_key) = &opts.combined_key {
    //         write_bytes_prefix(&mut buf, combined_key, uint8_writer)?;
    //     } else {
    //         write_bytes_prefix(&mut buf, &[], uint8_writer)?;
    //     }

    //     match opts.msg {
    //         None => buf.write_all(&[0x00])?,
    //         Some(ref msg) if msg.is_empty() => buf.write_all(&[0x00])?,
    //         Some(ref msg) => {
    //             buf.write_all(&[0x01])?;
    //             write_bytes_prefix(&mut buf, msg, uint64_writer)?;
    //         }
    //     }

    //     let aux = opts.aux_input.as_deref().unwrap_or(&[]);
    //     write_bytes_prefix(&mut buf, aux, uint32_writer)?;

    //     buf.write_u8(i)?;

    //     Ok(tagged_hash("MuSig/nonce", &buf))
    // }

    fn write_bytes_prefix(w: &mut dyn Write, b: &[u8], len_writer: LengthWriter) -> io::Result<()> {
        len_writer(w, b)?;
        w.write_all(b)?;
        Ok(())
    }

    fn uint8_writer(w: &mut dyn Write, b: &[u8]) -> io::Result<()> {
        w.write(&[b.len() as u8])?;
        Ok(())
    }

    fn uint32_writer(w: &mut dyn Write, b: &[u8]) -> io::Result<()> {
        w.write(&(b.len() as u32).to_be_bytes())?;
        Ok(())
    }

    fn uint64_writer(w: &mut dyn Write, b: &[u8]) -> io::Result<()> {
        w.write(&(b.len() as u64).to_be_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hex::DisplayHex;

    use super::*;
    #[test]
    fn test_writer() {
        let b = [0x89; 34];
        let mut w = Vec::new();
        MuSig2::uint8_writer(&mut w, &b).unwrap();
        assert_eq!("22", w.to_lower_hex_string());

        let mut w = Vec::new();
        MuSig2::uint32_writer(&mut w, &b).unwrap();
        assert_eq!("00000022", w.to_lower_hex_string());

        let mut w = Vec::new();
        MuSig2::uint64_writer(&mut w, &b).unwrap();
        assert_eq!("0000000000000022", w.to_lower_hex_string());

        let mut w = Vec::new();
        MuSig2::write_bytes_prefix(&mut w, &b, MuSig2::uint64_writer).unwrap();
        assert_eq!(
            "000000000000002289898989898989898989898989898989898989898989898989898989898989898989",
            w.to_lower_hex_string()
        );
    }
}
