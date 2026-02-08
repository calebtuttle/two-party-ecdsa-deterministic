/*
    Pure-Rust BigInt backend using num-bigint.

    This module provides a BigInt newtype wrapper around num_bigint::BigInt
    that implements the same API surface as the GMP-based Mpz type in big_gmp.rs.
    This enables WASM compilation by avoiding the C FFI dependency on libgmp.

    Activate with: --no-default-features --features num-bigint-backend
*/

use super::traits::{
    BitManipulation, ConvertFrom, Converter, Modulo, NumberTests, Samplable, EGCD,
};
use num_bigint::BigInt as InnerBigInt;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use rand::RngCore;
use std::borrow::Borrow;
use std::fmt;
use std::ops::{
    Add, AddAssign, BitAnd, BitXor, Div, Mul, Neg, Rem, Shl, ShlAssign, Shr, ShrAssign,
    Sub,
};
use std::str::FromStr;

use serde::de;
use serde::ser;

// ============== Type Definition ==============

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BigInt(pub(crate) InnerBigInt);

// ============== Debug & Display ==============

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigInt({})", self.0)
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============== Serde (hex string format, matching GMP's serde_support) ==============

const SERDE_RADIX: u32 = 16;

impl ser::Serialize for BigInt {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_str_radix(SERDE_RADIX))
    }
}

impl<'de> de::Deserialize<'de> for BigInt {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BigIntVisitor;

        impl<'de> de::Visitor<'de> for BigIntVisitor {
            type Value = BigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("BigInt")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<BigInt, E> {
                use num_traits::Num;
                Ok(BigInt(
                    InnerBigInt::from_str_radix(s, SERDE_RADIX)
                        .expect("Failed in serde"),
                ))
            }
        }

        deserializer.deserialize_str(BigIntVisitor)
    }
}

// ============== Constructors & Inherent Methods ==============

impl BigInt {
    pub fn zero() -> Self {
        BigInt(InnerBigInt::zero())
    }

    pub fn one() -> Self {
        BigInt(InnerBigInt::one())
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn bit_length(&self) -> usize {
        self.0.bits() as usize
    }

    pub fn to_str_radix(&self, radix: u8) -> String {
        self.0.to_str_radix(radix as u32)
    }

    pub fn from_str_radix(s: &str, radix: u8) -> Result<Self, num_bigint::ParseBigIntError> {
        use num_traits::Num;
        InnerBigInt::from_str_radix(s, radix as u32).map(BigInt)
    }

    pub fn mod_floor(&self, modulus: &Self) -> Self {
        BigInt(Integer::mod_floor(&self.0, &modulus.0))
    }

    pub fn div_floor(&self, other: &Self) -> Self {
        BigInt(Integer::div_floor(&self.0, &other.0))
    }

    pub fn powm(&self, exp: &Self, modulus: &Self) -> Self {
        BigInt(self.0.modpow(&exp.0, &modulus.0))
    }

    pub fn invert(&self, modulus: &Self) -> Option<Self> {
        let result = Integer::extended_gcd(&self.0, &modulus.0);
        if result.gcd == InnerBigInt::one() {
            Some(BigInt(Integer::mod_floor(&result.x, &modulus.0)))
        } else {
            None
        }
    }

    pub fn gcdext(&self, other: &Self) -> (Self, Self, Self) {
        let result = Integer::extended_gcd(&self.0, &other.0);
        (BigInt(result.gcd), BigInt(result.x), BigInt(result.y))
    }

    pub fn gcd(&self, other: &Self) -> Self {
        BigInt(Integer::gcd(&self.0, &other.0))
    }

    pub fn pow(&self, exp: u32) -> Self {
        BigInt(num_traits::pow::pow(self.0.clone(), exp as usize))
    }

    pub fn modulus(&self, m: &Self) -> Self {
        self.mod_floor(m)
    }

    pub fn is_multiple_of(&self, other: &Self) -> bool {
        if other.0.is_zero() {
            return self.0.is_zero();
        }
        (&self.0 % &other.0).is_zero()
    }

    pub fn tstbit(&self, bit: usize) -> bool {
        (&self.0 >> bit) & InnerBigInt::one() == InnerBigInt::one()
    }

    pub fn setbit(&mut self, bit: usize) {
        self.0 = &self.0 | (InnerBigInt::one() << bit);
    }

    pub fn clrbit(&mut self, bit: usize) {
        if self.tstbit(bit) {
            self.0 = &self.0 ^ (InnerBigInt::one() << bit);
        }
    }
}

// ============== From/Into Conversions ==============

impl From<i32> for BigInt {
    fn from(val: i32) -> Self {
        BigInt(InnerBigInt::from(val))
    }
}

impl From<u32> for BigInt {
    fn from(val: u32) -> Self {
        BigInt(InnerBigInt::from(val))
    }
}

impl From<i64> for BigInt {
    fn from(val: i64) -> Self {
        BigInt(InnerBigInt::from(val))
    }
}

impl From<u64> for BigInt {
    fn from(val: u64) -> Self {
        BigInt(InnerBigInt::from(val))
    }
}

// From byte slices: big-endian unsigned (matching GMP behavior)
impl From<&[u8]> for BigInt {
    fn from(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            BigInt(InnerBigInt::zero())
        } else {
            BigInt(InnerBigInt::from_bytes_be(Sign::Plus, bytes))
        }
    }
}

impl From<Vec<u8>> for BigInt {
    fn from(bytes: Vec<u8>) -> Self {
        BigInt::from(bytes.as_slice())
    }
}

// Into Vec<u8> for &BigInt: big-endian unsigned (matching GMP behavior)
impl<'a> From<&'a BigInt> for Vec<u8> {
    fn from(val: &'a BigInt) -> Vec<u8> {
        if val.0.is_zero() {
            return vec![0];
        }
        let (_sign, bytes) = val.0.to_bytes_be();
        bytes
    }
}

// FromStr: parse decimal string (used by paillier/zk_paillier serializers via str::parse)
impl FromStr for BigInt {
    type Err = num_bigint::ParseBigIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(BigInt(s.parse::<InnerBigInt>()?))
    }
}

// ============== Arithmetic Operators ==============

macro_rules! impl_binop {
    ($trait:ident, $method:ident) => {
        impl $trait for BigInt {
            type Output = BigInt;
            fn $method(self, rhs: BigInt) -> BigInt {
                BigInt($trait::$method(self.0, rhs.0))
            }
        }

        impl $trait<&BigInt> for BigInt {
            type Output = BigInt;
            fn $method(self, rhs: &BigInt) -> BigInt {
                BigInt($trait::$method(self.0, &rhs.0))
            }
        }

        impl $trait<BigInt> for &BigInt {
            type Output = BigInt;
            fn $method(self, rhs: BigInt) -> BigInt {
                BigInt($trait::$method(&self.0, rhs.0))
            }
        }

        impl<'a, 'b> $trait<&'b BigInt> for &'a BigInt {
            type Output = BigInt;
            fn $method(self, rhs: &'b BigInt) -> BigInt {
                BigInt($trait::$method(&self.0, &rhs.0))
            }
        }
    };
}

impl_binop!(Add, add);
impl_binop!(Sub, sub);
impl_binop!(Mul, mul);
impl_binop!(Div, div);
impl_binop!(Rem, rem);

// Negation
impl Neg for BigInt {
    type Output = BigInt;
    fn neg(self) -> BigInt {
        BigInt(-self.0)
    }
}

impl Neg for &BigInt {
    type Output = BigInt;
    fn neg(self) -> BigInt {
        BigInt(-&self.0)
    }
}

// Shift operators
impl Shl<usize> for BigInt {
    type Output = BigInt;
    fn shl(self, rhs: usize) -> BigInt {
        BigInt(self.0 << rhs)
    }
}

impl Shl<usize> for &BigInt {
    type Output = BigInt;
    fn shl(self, rhs: usize) -> BigInt {
        BigInt(&self.0 << rhs)
    }
}

impl Shr<usize> for BigInt {
    type Output = BigInt;
    fn shr(self, rhs: usize) -> BigInt {
        BigInt(self.0 >> rhs)
    }
}

impl Shr<usize> for &BigInt {
    type Output = BigInt;
    fn shr(self, rhs: usize) -> BigInt {
        BigInt(&self.0 >> rhs)
    }
}

// BitAnd
impl BitAnd for BigInt {
    type Output = BigInt;
    fn bitand(self, rhs: BigInt) -> BigInt {
        BigInt(self.0 & rhs.0)
    }
}

impl BitAnd<&BigInt> for BigInt {
    type Output = BigInt;
    fn bitand(self, rhs: &BigInt) -> BigInt {
        BigInt(self.0 & &rhs.0)
    }
}

impl<'a, 'b> BitAnd<&'b BigInt> for &'a BigInt {
    type Output = BigInt;
    fn bitand(self, rhs: &'b BigInt) -> BigInt {
        BigInt(&self.0 & &rhs.0)
    }
}

// BitXor
impl BitXor for BigInt {
    type Output = BigInt;
    fn bitxor(self, rhs: BigInt) -> BigInt {
        BigInt(self.0 ^ rhs.0)
    }
}

impl<'a, 'b> BitXor<&'b BigInt> for &'a BigInt {
    type Output = BigInt;
    fn bitxor(self, rhs: &'b BigInt) -> BigInt {
        BigInt(&self.0 ^ &rhs.0)
    }
}

// Assign operators
impl AddAssign for BigInt {
    fn add_assign(&mut self, rhs: BigInt) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&BigInt> for BigInt {
    fn add_assign(&mut self, rhs: &BigInt) {
        self.0 += &rhs.0;
    }
}

impl ShlAssign<usize> for BigInt {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}

impl ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, rhs: usize) {
        self.0 >>= rhs;
    }
}

// ============== Mixed Integer-BigInt Arithmetic ==============

macro_rules! impl_int_binop {
    ($int_ty:ty) => {
        // BigInt op int
        impl Add<$int_ty> for BigInt {
            type Output = BigInt;
            fn add(self, rhs: $int_ty) -> BigInt {
                BigInt(self.0 + InnerBigInt::from(rhs))
            }
        }

        impl Add<$int_ty> for &BigInt {
            type Output = BigInt;
            fn add(self, rhs: $int_ty) -> BigInt {
                BigInt(&self.0 + InnerBigInt::from(rhs))
            }
        }

        impl Sub<$int_ty> for BigInt {
            type Output = BigInt;
            fn sub(self, rhs: $int_ty) -> BigInt {
                BigInt(self.0 - InnerBigInt::from(rhs))
            }
        }

        impl Sub<$int_ty> for &BigInt {
            type Output = BigInt;
            fn sub(self, rhs: $int_ty) -> BigInt {
                BigInt(&self.0 - InnerBigInt::from(rhs))
            }
        }

        impl Mul<$int_ty> for BigInt {
            type Output = BigInt;
            fn mul(self, rhs: $int_ty) -> BigInt {
                BigInt(self.0 * InnerBigInt::from(rhs))
            }
        }

        impl Mul<$int_ty> for &BigInt {
            type Output = BigInt;
            fn mul(self, rhs: $int_ty) -> BigInt {
                BigInt(&self.0 * InnerBigInt::from(rhs))
            }
        }

        // int op BigInt
        impl Add<BigInt> for $int_ty {
            type Output = BigInt;
            fn add(self, rhs: BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) + rhs.0)
            }
        }

        impl Add<&BigInt> for $int_ty {
            type Output = BigInt;
            fn add(self, rhs: &BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) + &rhs.0)
            }
        }

        impl Sub<BigInt> for $int_ty {
            type Output = BigInt;
            fn sub(self, rhs: BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) - rhs.0)
            }
        }

        impl Sub<&BigInt> for $int_ty {
            type Output = BigInt;
            fn sub(self, rhs: &BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) - &rhs.0)
            }
        }

        impl Mul<BigInt> for $int_ty {
            type Output = BigInt;
            fn mul(self, rhs: BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) * rhs.0)
            }
        }

        impl Mul<&BigInt> for $int_ty {
            type Output = BigInt;
            fn mul(self, rhs: &BigInt) -> BigInt {
                BigInt(InnerBigInt::from(self) * &rhs.0)
            }
        }
    };
}

impl_int_binop!(i32);
impl_int_binop!(i64);
impl_int_binop!(u32);
impl_int_binop!(u64);

// ============== Custom Trait Implementations ==============

impl Converter for BigInt {
    fn to_vec(value: &BigInt) -> Vec<u8> {
        let bytes: Vec<u8> = value.borrow().into();
        bytes
    }

    fn to_hex(&self) -> String {
        self.to_str_radix(super::HEX_RADIX)
    }

    fn from_hex(value: &str) -> BigInt {
        BigInt::from_str_radix(value, super::HEX_RADIX).expect("Error in serialization")
    }
}

impl Modulo for BigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.powm(exponent, modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);
        (a_m * b_m).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);
        let sub_op = a_m - b_m + modulus;
        sub_op.mod_floor(modulus)
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);
        (a_m + b_m).mod_floor(modulus)
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        a.invert(modulus).unwrap()
    }
}

impl Samplable for BigInt {
    fn sample_below(upper: &Self) -> Self {
        assert!(upper > &BigInt::zero());
        let bits = upper.bit_length();
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        lower + &Self::sample_below(&(upper - lower))
    }

    fn strict_sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        loop {
            let n = lower + &Self::sample_below(&(upper - lower));
            if n > *lower && n < *upper {
                return n;
            }
        }
    }

    fn sample(bit_size: usize) -> Self {
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        rand::thread_rng().fill_bytes(&mut buf);
        BigInt::from(&*buf) >> (bytes * 8 - bit_size)
    }

    fn strict_sample(bit_size: usize) -> Self {
        loop {
            let n = Self::sample(bit_size);
            if n.bit_length() == bit_size {
                return n;
            }
        }
    }
}

impl NumberTests for BigInt {
    fn is_zero(me: &Self) -> bool {
        me.0.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.is_multiple_of(&BigInt::from(2))
    }
    fn is_negative(me: &Self) -> bool {
        me < &BigInt::from(0)
    }
}

impl EGCD for BigInt {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        a.gcdext(b)
    }
}

impl BitManipulation for BigInt {
    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        if bit_val {
            self.setbit(bit);
        } else {
            self.clrbit(bit);
        }
    }

    fn test_bit(&self, bit: usize) -> bool {
        self.tstbit(bit)
    }
}

impl ConvertFrom<BigInt> for u64 {
    fn _from(x: &BigInt) -> u64 {
        x.0.to_u64().unwrap()
    }
}

// ============== Tests ==============

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        BigInt::sample_below(&BigInt::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = BigInt::from(10);
        for _ in 1..100 {
            let r = BigInt::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        BigInt::sample_range(&BigInt::from(10), &BigInt::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = BigInt::from(10);
        let lower_bound = BigInt::from(5);
        for _ in 1..100 {
            let r = BigInt::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_range_test() {
        let len = 249;
        for _ in 1..100 {
            let a = BigInt::sample(len);
            let b = BigInt::sample(len);
            let lower_bound = cmp::min(a.clone(), b.clone());
            let upper_bound = cmp::max(a.clone(), b.clone());
            let r = BigInt::strict_sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_test() {
        let len = 249;
        for _ in 1..100 {
            let a = BigInt::strict_sample(len);
            assert_eq!(a.bit_length(), len);
        }
    }

    #[test]
    fn test_mod_sub_modulo() {
        let a = BigInt::from(10);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_sub_negative_modulo() {
        let a = BigInt::from(5);
        let b = BigInt::from(10);
        let modulo = BigInt::from(3);
        let res = BigInt::from(1);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_mul() {
        let a = BigInt::from(4);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_mul(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_pow() {
        let a = BigInt::from(2);
        let b = BigInt::from(3);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_pow(&a, &b, &modulo));
    }

    #[test]
    fn test_to_hex() {
        let b = BigInt::from(11);
        assert_eq!("b", b.to_hex());
    }

    #[test]
    fn test_from_hex() {
        let a = BigInt::from(11);
        assert_eq!(BigInt::from_hex(&a.to_hex()), a);
    }

    #[test]
    fn test_serde_roundtrip() {
        let a = BigInt::from(123456789);
        let serialized = serde_json::to_string(&a).unwrap();
        let deserialized: BigInt = serde_json::from_str(&serialized).unwrap();
        assert_eq!(a, deserialized);
    }

    #[test]
    fn test_byte_roundtrip() {
        let a = BigInt::from(256);
        let bytes: Vec<u8> = (&a).into();
        let b = BigInt::from(bytes.as_slice());
        assert_eq!(a, b);
    }

    #[test]
    fn test_invert() {
        let a = BigInt::from(3);
        let m = BigInt::from(7);
        let inv = a.invert(&m).unwrap();
        // 3 * 5 = 15 = 1 mod 7
        assert_eq!(inv, BigInt::from(5));
    }

    #[test]
    fn test_bit_operations() {
        let mut a = BigInt::from(0);
        a.setbit(3);
        assert_eq!(a, BigInt::from(8));
        assert!(a.tstbit(3));
        assert!(!a.tstbit(2));
        a.clrbit(3);
        assert_eq!(a, BigInt::from(0));
    }
}
