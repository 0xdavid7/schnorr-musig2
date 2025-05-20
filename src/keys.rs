// Public Key Aggregation
// 1. Challenge factor:
//      c_all = H(P0, P1, ..., Pn)
// 2. Aggregation coefficient:
//      c_i = H(c_all || P_i)
// 3. Aggregate public key:
//      P_agg = c_0 * P_0 + c_1 * P_1 + ... + c_n * P_n

use bitcoin::{
    hashes::{sha256::Hash as Sha256Hash, Hash},
    secp256k1::Scalar,
    PublicKey, TapTweakHash,
};

use super::{MuSig2, MuSig2Error};

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

#[derive(Debug)]
pub struct AggregateKey {
    final_key: PublicKey,
    pre_tweaked_key: PublicKey,
}

impl<'a> MuSig2<'a> {
    pub fn aggregate_keys(
        &self,
        keys: &[PublicKey],
        options: Vec<KeyAggOption>,
    ) -> Result<(AggregateKey, Scalar, Scalar), MuSig2Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
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
