use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use thiserror::Error;

pub struct MuSig2<'a> {
    secp: &'a Secp256k1<All>,
}

impl<'a> MuSig2<'a> {
    pub fn new(secp: &'a Secp256k1<All>) -> Self {
        Self { secp }
    }
}

#[derive(Debug, Clone)]
pub struct KeyTweakDesc {
    tweak: [u8; 32],
    is_x_only: bool,
}

#[derive(Debug)]
pub struct AggregateKey {
    final_key: PublicKey,
    pre_tweaked_key: PublicKey,
}

impl<'a> MuSig2<'a> {
    pub fn aggregate_keys(
        &self,
        keys: &[PublicKey],
        sort: bool,
        key_opts: &[KeyAggOption],
    ) -> Result<AggregateKey, MuSig2Error> {
        let mut opts = KeyAggOption::default();
        for option in key_opts {
            option.apply(&mut opts);
        }

        let sorted_keys = if sort {
            self.sort_keys(keys)
        } else {
            keys.to_vec()
        };

        if opts.key_hash.is_none() {
            opts.key_hash = Some(self.key_hash_fingerprint(&sorted_keys, sort));
        }

        if opts.unique_key_index.is_none() {
            opts.unique_key_index = Some(self.second_unique_key_index(&sorted_keys, sort));
        }

        let mut combined_key = None;

        for (i, key) in sorted_keys.iter().enumerate() {
            let a = self.aggregation_coefficient(
                &sorted_keys,
                key,
                opts.key_hash.as_ref().unwrap(),
                opts.unique_key_index.unwrap(),
            );
            let tweaked_key = key.mul_tweak(self.secp, &a)?;

            if i == 0 {
                combined_key = Some(tweaked_key);
            } else {
                combined_key = Some(combined_key.unwrap().combine(&tweaked_key)?);
            }
        }

        let final_key =
            combined_key.ok_or_else(|| MuSig2Error::Other(anyhow::anyhow!("No keys provided")))?;

        // TODO: will need to implement tweaking logic here
        // if opts.taproot_tweak {
        //     final_key = final_key.taproot_tweak(self.secp, &opts.taproot_tweak)?;
        // }

        // if opts.bip86_tweak {
        //     final_key = final_key.bip86_tweak(self.secp, &opts.bip86_tweak)?;
        // }

        Ok(AggregateKey {
            final_key,
            pre_tweaked_key: combined_key.unwrap(),
        })
    }

    fn sort_keys(&self, keys: &[PublicKey]) -> Vec<PublicKey> {
        let mut sorted_keys = keys.to_vec();
        sorted_keys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
        sorted_keys
    }

    fn key_hash_fingerprint(&self, keys: &[PublicKey], sort: bool) -> [u8; 32] {
        let sorted_keys = if sort {
            self.sort_keys(keys)
        } else {
            keys.to_vec()
        };
        let mut engine = sha256::HashEngine::default();
        engine.input(KEY_AGG_TAG_LIST);
        for key in sorted_keys {
            engine.input(&key.serialize());
        }
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    fn second_unique_key_index(&self, keys: &[PublicKey], sort: bool) -> i32 {
        let sorted_keys = if sort {
            self.sort_keys(keys)
        } else {
            keys.to_vec()
        };
        for (i, key) in sorted_keys.iter().enumerate().skip(1) {
            if key != &sorted_keys[0] {
                return i as i32;
            }
        }
        -1
    }

    fn aggregation_coefficient(
        &self,
        key_set: &[PublicKey],
        target_key: &PublicKey,
        keys_hash: &[u8; 32],
        second_key_idx: i32,
    ) -> bitcoin::secp256k1::Scalar {
        if second_key_idx != -1 && key_set[second_key_idx as usize] == *target_key {
            return bitcoin::secp256k1::Scalar::ONE;
        }

        let mut coefficient_bytes = [0u8; 65];
        coefficient_bytes[..32].copy_from_slice(keys_hash);
        coefficient_bytes[32..].copy_from_slice(&target_key.serialize());

        let mu_hash = tagged_hash(KEY_AGG_TAG_COEFF, &coefficient_bytes);
        bitcoin::secp256k1::Scalar::from_be_bytes(mu_hash).unwrap()
    }
}

#[derive(Default, Debug)]
pub struct KeyAggOption {
    key_hash: Option<[u8; 32]>,
    unique_key_index: Option<i32>,
    tweaks: Vec<KeyTweakDesc>,
    taproot_tweak: bool,
    bip86_tweak: bool,
}

impl KeyAggOption {
    pub fn with_keys_hash(key_hash: [u8; 32]) -> impl Fn(&mut KeyAggOption) {
        move |o: &mut KeyAggOption| {
            o.key_hash = Some(key_hash);
        }
    }

    pub fn with_unique_key_index(idx: i32) -> impl Fn(&mut KeyAggOption) {
        move |o: &mut KeyAggOption| {
            o.unique_key_index = Some(idx);
        }
    }

    pub fn with_key_tweaks(tweaks: Vec<KeyTweakDesc>) -> impl Fn(&mut KeyAggOption) {
        move |o: &mut KeyAggOption| {
            o.tweaks = tweaks.clone();
        }
    }

    pub fn apply(&self, opts: &mut KeyAggOption) {
        if let Some(key_hash) = self.key_hash {
            opts.key_hash = Some(key_hash);
        }
        if let Some(unique_key_index) = self.unique_key_index {
            opts.unique_key_index = Some(unique_key_index);
        }
        if !self.tweaks.is_empty() {
            opts.tweaks = self.tweaks.clone();
        }
        opts.taproot_tweak = self.taproot_tweak;
        opts.bip86_tweak = self.bip86_tweak;
    }
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    let tag_hash = sha256::Hash::hash(tag);
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    static PUBKEY1: [u8; 33] = [
        0x03, 0x2b, 0xc2, 0xcf, 0xa7, 0x26, 0x4c, 0x49, 0x6a, 0x23, 0xe3, 0xf7, 0x35, 0xb2, 0xbb,
        0x58, 0x6e, 0xa7, 0xac, 0xe3, 0x95, 0x3f, 0xb5, 0x55, 0x62, 0x06, 0xa6, 0x8f, 0x74, 0x44,
        0x06, 0xfc, 0x45,
    ];

    static PUBKEY2: [u8; 33] = [
        0x03, 0xd9, 0xb9, 0x8e, 0xf2, 0xc5, 0x80, 0x41, 0x6c, 0xa8, 0x28, 0x80, 0x1f, 0x5c, 0x3d,
        0x0a, 0xfb, 0x81, 0xb1, 0x06, 0x39, 0xf5, 0xb5, 0xa1, 0xab, 0xe8, 0x1d, 0xad, 0x89, 0xaf,
        0x77, 0x79, 0xaf,
    ];

    #[test]
    fn test_aggregate_public_keys() {
        let secp = Secp256k1::new();
        let keys = vec![
            PublicKey::from_slice(&PUBKEY1).unwrap(),
            PublicKey::from_slice(&PUBKEY2).unwrap(),
        ];

        assert_eq!(
            keys[0].to_string(),
            "032bc2cfa7264c496a23e3f735b2bb586ea7ace3953fb5556206a68f744406fc45"
        );

        assert_eq!(
            keys[1].to_string(),
            "03d9b98ef2c580416ca828801f5c3d0afb81b10639f5b5a1abe81dad89af7779af"
        );

        let musig = MuSig2::new(&secp);

        let agg = musig.aggregate_keys(&keys, false, &[]).unwrap();
        // assert_eq!(agg.is_ok(), true);

        println!("Aggregated key: {:?}", agg.final_key.to_string());
    }
}
