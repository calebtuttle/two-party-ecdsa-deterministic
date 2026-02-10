/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

pub mod elliptic;

mod secp256k1instance {
    pub use crate::curv::elliptic::curves::secp256_k1::FE;
    pub use crate::curv::elliptic::curves::secp256_k1::GE;
    pub use crate::curv::elliptic::curves::secp256_k1::PK;
    pub use crate::curv::elliptic::curves::secp256_k1::SK;
}

pub use self::secp256k1instance::*;

pub mod arithmetic;

#[cfg(feature = "gmp-backend")]
pub use arithmetic::big_gmp::BigInt;

#[cfg(feature = "num-bigint-backend")]
pub use arithmetic::big_num::BigInt;

#[cfg(feature = "js-bigint-backend")]
pub use arithmetic::big_js::BigInt;

pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}
