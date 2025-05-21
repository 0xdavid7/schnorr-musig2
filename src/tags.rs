use bitcoin::{
    hashes::{
        sha256::{self},
        sha256t_hash_newtype, Hash, HashEngine,
    },
    PublicKey,
};

sha256t_hash_newtype! {
    pub struct KeyAggCoeffTag = hash_str("KeyAgg coefficient");

    /// Taproot-tagged hash with tag \"KeyAgg coefficient\".
    ///
    /// This is used for computing chanllenge factor for key aggregation.
    // #[hash_newtype(forward)]
    pub struct KeyAggCoeffHash(_);

    pub struct KeyAggListTag = hash_str("KeyAgg list");

    /// Taproot-tagged hash with tag \"KeyAgg list\".
    ///
    /// This is used for computing chanllenge factor for key aggregation.
    #[hash_newtype(forward)]
    pub struct KeyAggListHash(_);
}

impl KeyAggListHash {
    /// Create a new [`KeyAggListHash`] from a list of public keys.
    /// h = H(Tagged_Hash || Tagged_Hash || P0 || P1 || ... || Pn)
    pub fn from_public_keys(keys: &[PublicKey]) -> KeyAggListHash {
        let mut engine = KeyAggListHash::engine();
        for key in keys {
            engine.input(&key.inner.serialize());
        }

        KeyAggListHash::from_engine(engine)
    }
}

impl From<KeyAggCoeffHash> for sha256::Hash {
    fn from(val: KeyAggCoeffHash) -> Self {
        sha256::Hash::from_byte_array(val.to_byte_array())
    }
}

impl From<KeyAggCoeffHash> for [u8; 32] {
    fn from(val: KeyAggCoeffHash) -> Self {
        val.to_byte_array()
    }
}

impl From<KeyAggListHash> for sha256::Hash {
    fn from(val: KeyAggListHash) -> Self {
        sha256::Hash::from_byte_array(val.to_byte_array())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_agg_list_hash() {
        let keys = &vec![PublicKey::from_slice(
            &[0x02]
                .iter()
                .chain([0x08; 32].iter())
                .copied()
                .collect::<Vec<u8>>(),
        )
        .unwrap()];

        let h = KeyAggListHash::from_public_keys(keys);

        assert_eq!(
            h,
            KeyAggListHash::from_str(
                "9c63758509d81be9ed2be6089c71609c50f11f194241158e3863c1583e97a7b8"
            )
            .unwrap()
        );
    }
}
