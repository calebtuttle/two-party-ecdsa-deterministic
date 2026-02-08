/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

#[cfg(feature = "secp256k1-backend")]
pub mod secp256_k1;

#[cfg(feature = "k256-backend")]
#[path = "secp256_k1_k256.rs"]
pub mod secp256_k1;

pub mod traits;
