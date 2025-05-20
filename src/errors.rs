use thiserror::Error;

#[derive(Error, Debug)]
pub enum MuSig2Error {
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    #[error("Tweaked key is infinity point")]
    TweakedKeyIsInfinity,
    #[error("Tweaked key is too large")]
    TweakedKeyOverflows,
}
