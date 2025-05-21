use bitcoin::secp256k1;

use crate::errors::MuSig2Error;

pub trait ExtendedSecp256k1Scalar {
    fn from_k256(scalar: k256::Scalar) -> Result<secp256k1::Scalar, MuSig2Error>;
}

impl ExtendedSecp256k1Scalar for secp256k1::Scalar {
    // Currently bitcoin::secp256k1::Scalar doesn't support primitive arithmetics,
    // so I have to use k256 lib
    // this transformation is for mul_tweak purpose
    // TODO: check bitcoin::secp256k1::Scalar frequently for new updates or explore some Rust's libs
    // that support Jacobian points
    fn from_k256(scalar: k256::Scalar) -> Result<secp256k1::Scalar, MuSig2Error> {
        let mut data: [u8; 32] = [0; 32];
        data.copy_from_slice(&scalar.to_bytes());
        secp256k1::Scalar::from_be_bytes(data)
            .map_err(|_| MuSig2Error::Other(anyhow::anyhow!("Invalid parity factor")))
    }
}
