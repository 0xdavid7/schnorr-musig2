// Public Key Aggregation
// 1. Challenge factor:
//      c_all = H(P0, P1, ..., Pn)
// 2. Aggregation coefficient:
//      c_i = H(c_all || P_i)
// 3. Aggregate public key:
//      P_agg = c_0 * P_0 + c_1 * P_1 + ... + c_n * P_n

use bitcoin::{
    hashes::{sha256::Hash as Sha256Hash, Hash},
    secp256k1::{self, SecretKey},
    PublicKey, TapTweakHash,
};
use k256::{
    elliptic_curve::{bigint::U256, scalar::FromUintUnchecked},
    Scalar,
};

use crate::{
    errors::{MuSig2Error, MuSig2Result},
    scalar::ExtendedSecp256k1Scalar,
    tags::{KeyAggCoeffHash, KeyAggListHash},
    MuSig2, N_BYTES, N_PUBKEY,
};

type KeyAggOptionModifer = Box<dyn Fn(&mut KeyAggOption)>;

#[derive(Debug, Clone, Copy)]
pub struct KeyTweakDesc {
    tweak: TapTweakHash,
    is_x_only: bool,
}

#[derive(Default, Debug)]
pub struct KeyAggOption {
    // this is the hash of all the keys
    pub challenge_factor: Option<Sha256Hash>,

    // pre-computed index of second unique key for hashing optimization
    pub unique_key_index: Option<i32>,

    // list of tweaks to apply to the final key
    pub tweaks: Vec<KeyTweakDesc>,

    // if true, the tweaks above should be applied in a BIP-340 style (Schnorr)
    pub taproot_tweak: bool,

    // if true, the tweaks above should be applied in a BIP-0086 style (create key path spend-only P2TR outputs)
    pub bip86_tweak: bool,
}

impl KeyAggOption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_challenge_factor(c: Sha256Hash) -> impl Fn(&mut KeyAggOption) {
        move |o| {
            o.challenge_factor = Some(c);
        }
    }

    pub fn with_unique_key_index(unique_key_index: i32) -> impl Fn(&mut KeyAggOption) {
        // set the unique key index to the given value
        // this is used for hashing optimization
        move |o| {
            o.unique_key_index = Some(unique_key_index);
        }
    }

    pub fn with_tweaks(tweaks: Vec<KeyTweakDesc>) -> impl Fn(&mut KeyAggOption) {
        move |o| {
            o.tweaks = tweaks.clone();
        }
    }

    // // use the taproot tweak, output_key = internal_key  + h_tap_tweak(internal_key || script_root)
    pub fn with_taproot_tweak(script_root: Sha256Hash) -> impl Fn(&mut KeyAggOption) {
        move |o| {
            o.taproot_tweak = true;
            o.tweaks.push(KeyTweakDesc {
                tweak: TapTweakHash::from_byte_array(script_root.to_byte_array()),
                is_x_only: true,
            });
        }
    }

    pub fn with_bip86_tweak() -> impl Fn(&mut KeyAggOption) {
        move |o| {
            o.bip86_tweak = true;
            o.taproot_tweak = true;
        }
    }

    pub fn apply(&mut self, modifiers: &[KeyAggOptionModifer]) {
        for modifier in modifiers {
            modifier(self);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AggregateKey {
    final_key: PublicKey,
    pre_tweaked_key: PublicKey,
}

impl MuSig2<'_> {
    pub fn aggregate_keys(
        &self,
        keys: &[PublicKey],
        sort: bool,
        modifiers: Option<&[KeyAggOptionModifer]>,
    ) -> MuSig2Result<(AggregateKey, Scalar, Scalar)> {
        let mut opts = KeyAggOption::new();
        if let Some(modifiers) = modifiers {
            opts.apply(modifiers);
        }

        let mut sorted_keys = keys.to_owned();
        if sort {
            Self::sort_keys(&mut sorted_keys);
        }

        if opts.challenge_factor.is_none() {
            opts.challenge_factor = Some(Self::caculate_challenge_factor(&sorted_keys));
        }

        if opts.unique_key_index.is_none() {
            opts.unique_key_index = Some(Self::second_unique_key_index(&sorted_keys));
        }

        let mut combined_key = None;

        for (i, key) in sorted_keys.iter().enumerate() {
            let a = self.aggregation_coefficient(
                &sorted_keys,
                key,
                opts.challenge_factor.as_ref().unwrap(),
                opts.unique_key_index.unwrap(),
            );

            // Note: Need to deep dive into concerning about Jacobian coordinates
            let tweaked_key = key.inner.mul_tweak(self.secp, &a)?;

            if i == 0 {
                combined_key = Some(tweaked_key);
            } else {
                combined_key = Some(combined_key.unwrap().combine(&tweaked_key)?);
            }
        }

        let final_key =
            combined_key.ok_or_else(|| MuSig2Error::Other(anyhow::anyhow!("No keys provided")))?;

        // Store the pre-tweaked key for script path proofs
        let combined_key = PublicKey::new(final_key);

        // Handle taproot tweaking if enabled
        if opts.taproot_tweak {
            // Convert to x-only public key format
            let (key_bytes, _) = combined_key.inner.x_only_public_key();
            let key_slice = key_bytes.serialize();

            // Use empty tweak bytes for BIP-0086, otherwise use provided tweak
            let tweak_bytes: Vec<u8> = if opts.bip86_tweak {
                vec![]
            } else if !opts.tweaks.is_empty() {
                opts.tweaks[0].tweak.to_byte_array().to_vec()
            } else {
                vec![]
            };

            // Compute taproot tagged hash: h_tapTweak(data)
            // data = internalKey || tweakBytes

            let mut data = Vec::new();
            data.extend_from_slice(&key_slice);
            data.extend_from_slice(&tweak_bytes);
            let tap_tweak_hash = TapTweakHash::hash(&data);

            // overwrite the tweak with the tap_tweak_hash
            if !opts.tweaks.is_empty() {
                opts.tweaks[0].tweak = tap_tweak_hash;
            } else {
                opts.tweaks.push(KeyTweakDesc {
                    tweak: tap_tweak_hash,
                    is_x_only: true,
                });
            }
        }

        let mut parity_acc = Scalar::ONE;
        let mut tweak_acc = Scalar::ZERO;
        let mut final_tweak_key_acc = final_key;

        for tweak in opts.tweaks.iter() {
            self.tweak_key(
                &mut final_tweak_key_acc,
                &mut parity_acc,
                &mut tweak_acc,
                &tweak.tweak,
                tweak.is_x_only,
            )?;
        }

        let final_tweaked_key = PublicKey::new(final_tweak_key_acc);

        Ok((
            AggregateKey {
                pre_tweaked_key: combined_key,
                final_key: final_tweaked_key,
            },
            parity_acc,
            tweak_acc,
        ))
    }

    /// c_i = H(c_all || P_i)
    /// This function is used to calculate the aggregation coefficient for a given key
    /// If the target key is the same as the key at the second key index, return 1
    /// Otherwise, return the aggregation coefficient for the given key
    /// For example:
    /// Keys = [K1, K2, K3, K1, K2]
    /// Second key index = 1
    /// Key0 -> c_i = H(c_all || K1)
    fn aggregation_coefficient(
        &self,
        key_set: &[PublicKey],
        target_key: &PublicKey,
        challenge_factor: &Sha256Hash,
        second_key_idx: i32,
    ) -> bitcoin::secp256k1::Scalar {
        if second_key_idx != -1 && key_set[second_key_idx as usize] == *target_key {
            return bitcoin::secp256k1::Scalar::ONE;
        }

        let mut coefficient_bytes = [0u8; N_BYTES + N_PUBKEY];
        coefficient_bytes[..N_BYTES].copy_from_slice(challenge_factor.as_ref());
        coefficient_bytes[N_BYTES..].copy_from_slice(&target_key.inner.serialize());

        let hash = KeyAggCoeffHash::hash(&coefficient_bytes);

        bitcoin::secp256k1::Scalar::from_be_bytes(hash.into()).unwrap()
    }

    fn tweak_key(
        &self,
        key: &mut secp256k1::PublicKey,
        parity_acc: &mut Scalar,
        tweak_acc: &mut Scalar,
        tweak: &TapTweakHash,
        x_only: bool,
    ) -> MuSig2Result<()> {
        // First compute the parity factor based on y-coordinate
        let parity_factor = if x_only && !Self::has_even_y(key) {
            Scalar::ONE.negate()
        } else {
            Scalar::ONE
        };

        let secp256k1_scalar =
            <secp256k1::Scalar as ExtendedSecp256k1Scalar>::from_k256(parity_factor)?;

        // Compute g*Q (where g is parity_factor)
        let mut tweaked_key = key.mul_tweak(self.secp, &secp256k1_scalar)?;

        let tweak_scalar = SecretKey::from_slice(tweak.as_byte_array())
            .map_err(|_| MuSig2Error::Other(anyhow::anyhow!("Invalid tweak")))?;

        // Compute t*G (where t is tweak_scalar)
        let generator_point = secp256k1::PublicKey::from_secret_key(self.secp, &tweak_scalar);

        // Add t*G to g*Q
        tweaked_key = tweaked_key.combine(&generator_point)?;

        // Update the accumulated values

        let tweak_scalar = Scalar::from_uint_unchecked(U256::from_be_slice(tweak.as_byte_array()));

        *parity_acc = parity_acc.mul(&parity_factor);
        *tweak_acc = tweak_acc.mul(&parity_factor).add(&tweak_scalar);
        *key = tweaked_key;

        Ok(())
    }

    /// c_all = Tagged_Hash(P0, P1, ..., Pn)
    pub fn caculate_challenge_factor(keys: &[PublicKey]) -> Sha256Hash {
        KeyAggListHash::from_public_keys(keys).into()
    }

    /// This function is used to find the index of the second unique key in the list of keys
    /// If all keys are the same, return -1
    /// If there is only one key, return 0
    fn second_unique_key_index(keys: &[PublicKey]) -> i32 {
        for (i, key) in keys.iter().enumerate().skip(1) {
            if key != &keys[0] {
                return i as i32;
            }
        }
        -1
    }

    fn sort_keys(keys: &mut [PublicKey]) {
        if keys.is_sorted() {
            return;
        }
        keys.sort();
    }

    fn has_even_y(key: &secp256k1::PublicKey) -> bool {
        let key_bytes = key.serialize();
        match key_bytes[0] {
            0x02 => true,
            0x03 => false,
            _ => panic!("Invalid public key"),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::hex::DisplayHex;
    use lazy_static::lazy_static;

    use super::*;

    lazy_static! {
        static ref MOCK_KEYS: Vec<PublicKey> = {
            let mut keys = vec![
                PublicKey::from_slice(
                    &[0x02]
                        .iter()
                        .chain([0x08; N_BYTES].iter())
                        .copied()
                        .collect::<Vec<u8>>(),
                )
                .unwrap(),
                PublicKey::from_slice(
                    &[0x02]
                        .iter()
                        .chain([0x01; N_BYTES].iter())
                        .copied()
                        .collect::<Vec<u8>>(),
                )
                .unwrap(),
                PublicKey::from_slice(
                    &[0x02]
                        .iter()
                        .chain([0x07; N_BYTES].iter())
                        .copied()
                        .collect::<Vec<u8>>(),
                )
                .unwrap(),
            ];

            MuSig2::sort_keys(&mut keys);
            keys
        };
    }

    #[test]
    fn test_simple_aggregate_keys() {
        let keys = MOCK_KEYS.clone();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let musig2 = MuSig2::new(&secp);
        let (agg, parity_acc, tweak_acc) = musig2.aggregate_keys(&keys, true, None).unwrap();

        assert_eq!(
            "02fa4785e10a19dae7c518c69dbac060a22be49a43e8c9b8a71d8f933a91640443",
            agg.final_key.inner.serialize().to_lower_hex_string()
        );

        assert_eq!(
            "0000000000000000000000000000000000000000000000000000000000000001",
            parity_acc.to_bytes().to_lower_hex_string()
        );

        assert_eq!(
            "0000000000000000000000000000000000000000000000000000000000000000",
            tweak_acc.to_bytes().to_lower_hex_string()
        )
    }

    #[test]
    fn test_aggregate_keys_with_tweak() {
        let keys = MOCK_KEYS.clone();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let musig2 = MuSig2::new(&secp);

        let options: Vec<KeyAggOptionModifer> =
            vec![Box::new(KeyAggOption::with_tweaks(vec![KeyTweakDesc {
                tweak: TapTweakHash::from_byte_array([0x02; N_BYTES]),
                is_x_only: true,
            }]))];

        let (agg, parity_acc, tweak_acc) =
            musig2.aggregate_keys(&keys, true, Some(&options)).unwrap();

        assert_eq!(
            "028408bedd457c1f085788a8825c615b1f10544f53ece0d758b69fa4b294179b1a",
            agg.final_key.inner.serialize().to_lower_hex_string()
        );

        assert_eq!(
            "0000000000000000000000000000000000000000000000000000000000000001",
            parity_acc.to_bytes().to_lower_hex_string()
        );

        assert_eq!(
            "0202020202020202020202020202020202020202020202020202020202020202",
            tweak_acc.to_bytes().to_lower_hex_string()
        );
    }

    #[test]
    fn test_tweak_key() {
        let mut pubkey = secp256k1::PublicKey::from_str(
            "02fa4785e10a19dae7c518c69dbac060a22be49a43e8c9b8a71d8f933a91640443",
        )
        .unwrap();

        let secp = secp256k1::Secp256k1::new();

        let mut parity_acc = Scalar::ONE;
        let mut tweak_acc = Scalar::ZERO;
        let tweak = TapTweakHash::from_byte_array([0x1; N_BYTES]);

        MuSig2::new(&secp)
            .tweak_key(&mut pubkey, &mut parity_acc, &mut tweak_acc, &tweak, true)
            .unwrap();

        assert_eq!(
            pubkey.serialize().to_lower_hex_string(),
            "025f9d9693726d94483d7c83c17272158543c7366081511d231c3e6bfdbd87d94b"
        );

        assert_eq!(
            parity_acc.to_bytes().to_lower_hex_string(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        assert_eq!(
            tweak_acc.to_bytes().to_lower_hex_string(),
            "0101010101010101010101010101010101010101010101010101010101010101"
        )
    }

    #[test]
    fn test_arithmetic() {
        let one_negated = Scalar::ONE.negate();
        let mut data: [u8; N_BYTES] = [0x00; N_BYTES];
        // copy one_negated to data
        data.copy_from_slice(&one_negated.to_bytes().as_slice());

        let one_negated = secp256k1::Scalar::from_be_bytes(data).unwrap();

        assert_eq!(
            one_negated.to_be_bytes().to_lower_hex_string(),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        )
    }

    #[test]
    fn test_caculate_challenge_factor() {
        let mut keys = MOCK_KEYS.clone();
        MuSig2::sort_keys(&mut keys);
        let challenge_factor = MuSig2::caculate_challenge_factor(&keys);
        assert_eq!(
            challenge_factor,
            Sha256Hash::from_str(
                "ba8ced89a6d45d58616bd38c4833e56da6aa6e2e384498b5a61a5c570ed23915"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_key_options() {
        let mut opts = KeyAggOption::new();

        let challenge_factor = Sha256Hash::hash(b"hello");

        let options: Vec<KeyAggOptionModifer> = vec![
            Box::new(KeyAggOption::with_challenge_factor(challenge_factor)),
            Box::new(KeyAggOption::with_unique_key_index(1)),
        ];

        opts.apply(&options);

        assert_eq!(opts.challenge_factor.unwrap(), challenge_factor);
        assert_eq!(opts.unique_key_index.unwrap(), 1);
    }
}
