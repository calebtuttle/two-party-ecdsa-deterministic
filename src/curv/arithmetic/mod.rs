/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

const HEX_RADIX: u8 = 16;

#[cfg(feature = "gmp-backend")]
pub mod big_gmp;

#[cfg(feature = "num-bigint-backend")]
pub mod big_num;

#[cfg(feature = "js-bigint-backend")]
pub mod big_js;

pub mod traits;
