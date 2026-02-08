#![allow(non_snake_case)]
//! Pure-Rust secp256k1 implementation using k256 for WASM compatibility.

use std::any::Any;
use super::traits::{ECPoint, ECScalar};
use crate::curv::arithmetic::traits::{Converter, Modulo};
use crate::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
use crate::curv::BigInt;
use crate::curv::ErrorKey;
use crate::party_one::Value;
use rand::thread_rng;
use serde::de;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Deref, Mul, Neg};
use zeroize::Zeroize;

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Field, PrimeField};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

// ============ Inner Types ============

/// 32-byte scalar with Deref<[u8]> for byte access.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SK(pub [u8; 32]);

impl SK {
    pub fn from_slice(data: &[u8]) -> Result<SK, String> {
        if data.len() != 32 { return Err(format!("Invalid key size: {}", data.len())); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(data);
        Ok(SK(arr))
    }

    pub fn len(&self) -> usize { 32 }

    /// Returns the 32-byte secret key (matches secp256k1::SecretKey API).
    pub fn serialize_secret(&self) -> [u8; 32] { self.0 }

    fn to_scalar(&self) -> Scalar {
        if self.0 == [0u8; 32] { return Scalar::ZERO; }
        Option::from(Scalar::from_repr(self.0.into())).expect("Invalid scalar")
    }
}

impl From<Scalar> for SK {
    fn from(s: Scalar) -> SK {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&s.to_repr());
        SK(bytes)
    }
}

impl fmt::Debug for SK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SK([REDACTED])") }
}

impl Deref for SK {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}

/// 65-byte uncompressed SEC1 public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PK(pub [u8; 65]);

impl PK {
    pub fn from_slice(data: &[u8]) -> Result<PK, String> {
        let encoded = EncodedPoint::from_bytes(data).map_err(|e| format!("{e}"))?;
        let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        let affine = affine.ok_or("Invalid curve point")?;
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(affine.to_encoded_point(false).as_bytes());
        Ok(PK(bytes))
    }

    pub fn is_identity(&self) -> bool { self.0 == [0u8; 65] }

    pub fn serialize(&self) -> [u8; 33] {
        if self.is_identity() { return [0u8; 33]; }
        let mut r = [0u8; 33];
        r.copy_from_slice(self.to_affine().to_encoded_point(true).as_bytes());
        r
    }

    pub fn serialize_uncompressed(&self) -> [u8; 65] { self.0 }

    fn to_affine(&self) -> AffinePoint {
        let ep = EncodedPoint::from_bytes(&self.0).unwrap();
        Option::from(AffinePoint::from_encoded_point(&ep)).unwrap()
    }

    pub fn to_projective(&self) -> ProjectivePoint {
        if self.is_identity() { return ProjectivePoint::IDENTITY; }
        ProjectivePoint::from(self.to_affine())
    }
}

impl From<&ProjectivePoint> for PK {
    fn from(p: &ProjectivePoint) -> PK {
        use k256::elliptic_curve::Group;
        if bool::from(p.is_identity()) { return PK([0u8; 65]); }
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(p.to_affine().to_encoded_point(false).as_bytes());
        PK(bytes)
    }
}

// ============ Main Types ============

pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

/// Wrapper around SK bytes with a debug-only purpose tag.
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Scalar {
    purpose: &'static str, // zero-cost debug tag used in the rest of the library
    fe: SK,
}

/// Wrapper around PK bytes with a debug-only purpose tag.
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Point {
    purpose: &'static str,
    ge: PK,
}

// ============ Trait Impls ============

#[typetag::serde]
impl Value for Secp256k1Point {
    fn as_any(&self) -> &dyn Any { self }
    fn type_name(&self) -> &str { "Secp256k1Point" }
}

impl fmt::Display for Secp256k1Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}

// Zeroize delegates to the zeroize crate's safe volatile-write impl for [u8; N].
impl Zeroize for FE {
    fn zeroize(&mut self) { self.fe.0.zeroize(); }
}

impl Zeroize for GE {
    fn zeroize(&mut self) { self.ge.0.zeroize(); }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Self) -> bool { self.fe == other.fe }
}

impl PartialEq for Secp256k1Point {
    fn eq(&self, other: &Self) -> bool { self.ge == other.ge }
}

// ============ ECScalar ============

impl ECScalar<SK> for Secp256k1Scalar {
    fn new_random() -> Secp256k1Scalar {
        let scalar = Scalar::random(&mut thread_rng());
        Secp256k1Scalar { purpose: "random", fe: SK::from(scalar) }
    }

    fn zero() -> Secp256k1Scalar {
        Secp256k1Scalar { purpose: "zero", fe: SK([0u8; 32]) }
    }

    fn get_element(&self) -> SK { self.fe }
    fn set_element(&mut self, element: SK) { self.fe = element }

    fn from(n: &BigInt) -> Secp256k1Scalar {
        let q = FE::q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0), &q);
        let mut v = BigInt::to_vec(&n_reduced);
        if v.len() < 32 {
            let mut pad = vec![0; 32 - v.len()];
            pad.extend_from_slice(&v);
            v = pad;
        }
        Secp256k1Scalar { purpose: "from_big_int", fe: SK::from_slice(&v).unwrap() }
    }

    fn to_big_int(&self) -> BigInt { BigInt::from(&self.fe[..]) }

    fn q() -> BigInt {
        // Derive order from k256: -1 in scalar field = n-1
        BigInt::from(&(-Scalar::ONE).to_repr()[..]) + BigInt::from(1)
    }

    // Native k256 scalar arithmetic (no BigInt roundtrip)
    fn add(&self, other: &SK) -> Secp256k1Scalar {
        Secp256k1Scalar { purpose: "add", fe: SK::from(self.fe.to_scalar() + other.to_scalar()) }
    }

    fn mul(&self, other: &SK) -> Secp256k1Scalar {
        Secp256k1Scalar { purpose: "mul", fe: SK::from(self.fe.to_scalar() * other.to_scalar()) }
    }

    fn sub(&self, other: &SK) -> Secp256k1Scalar {
        Secp256k1Scalar { purpose: "sub", fe: SK::from(self.fe.to_scalar() - other.to_scalar()) }
    }

    fn invert(&self) -> Secp256k1Scalar {
        let inv: Scalar = Option::from(self.fe.to_scalar().invert()).expect("Cannot invert zero");
        Secp256k1Scalar { purpose: "invert", fe: SK::from(inv) }
    }
}

// Operator impls provide `scalar + scalar` and `scalar * scalar` syntax,
// delegating to the ECScalar trait methods which take `&SK`.

impl Mul<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: Secp256k1Scalar) -> Self::Output { (&self).mul(&other.get_element()) }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output { (&self).mul(&other.get_element()) }
}

impl Add<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: Secp256k1Scalar) -> Self::Output { (&self).add(&other.get_element()) }
}

impl<'o> Add<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: &'o Secp256k1Scalar) -> Self::Output { (&self).add(&other.get_element()) }
}

// Scalar serde (hex string format, matching the secp256k1 backend)

impl Serialize for Secp256k1Scalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Secp256k1Scalar;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("hex string") }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Secp256k1Scalar, E> {
        Ok(ECScalar::from(&BigInt::from_str_radix(s, 16).expect("Invalid hex")))
    }
}

// ============ ECPoint ============

impl Secp256k1Point {
    pub fn random_point() -> Secp256k1Point {
        let s: Secp256k1Scalar = Secp256k1Scalar::new_random();
        let pk = Secp256k1Point::generator().scalar_mul(&s.get_element());
        Secp256k1Point { purpose: "random_point", ge: pk.get_element() }
    }

    /// Deterministic second generator derived by hashing G (for Centipede protocol).
    pub fn base_point2() -> Secp256k1Point {
        let g: Secp256k1Point = ECPoint::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&[&hash]);
        let hash = HSha256::create_hash(&[&hash]);
        let mut hash_vec = BigInt::to_vec(&hash);
        let mut template: Vec<u8> = vec![2];
        template.append(&mut hash_vec);
        Secp256k1Point { purpose: "random", ge: PK::from_slice(&template).unwrap() }
    }
}

impl ECPoint<PK, SK> for Secp256k1Point {
    fn generator() -> Secp256k1Point {
        Secp256k1Point { purpose: "base_fe", ge: PK::from(&ProjectivePoint::GENERATOR) }
    }

    fn get_element(&self) -> PK { self.ge }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from(&self.ge.serialize()[..])
    }

    fn x_coor(&self) -> Option<BigInt> { Some(BigInt::from(&self.ge.0[1..33])) }
    fn y_coor(&self) -> Option<BigInt> { Some(BigInt::from(&self.ge.0[33..65])) }

    fn from_bytes(bytes: &[u8]) -> Result<Secp256k1Point, ErrorKey> {
        // Build SEC1 encoding from raw coordinate bytes (matching secp256k1 backend behavior)
        let sec1 = match bytes.len() {
            0..=32 => {
                let mut v = vec![0; 32 - bytes.len()];
                v.extend_from_slice(bytes);
                [vec![2u8], v].concat() // compressed
            }
            33..=63 => {
                let mut v = vec![0; 64 - bytes.len()];
                v.extend_from_slice(bytes);
                [vec![4u8], v].concat() // uncompressed
            }
            _ => [vec![4u8], bytes[..64].to_vec()].concat(),
        };
        PK::from_slice(&sec1)
            .map(|pk| Secp256k1Point { purpose: "from_bytes", ge: pk })
            .map_err(|_| ErrorKey::InvalidPublicKey)
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut v = vec![4u8];
        v.extend(BigInt::to_vec(&self.x_coor().unwrap()));
        v.extend(BigInt::to_vec(&self.y_coor().unwrap()));
        v
    }

    fn scalar_mul(&self, fe: &SK) -> Secp256k1Point {
        let result = self.ge.to_projective() * fe.to_scalar();
        Secp256k1Point { purpose: "mul", ge: PK::from(&result) }
    }

    fn add_point(&self, other: &PK) -> Secp256k1Point {
        let result = self.ge.to_projective() + other.to_projective();
        Secp256k1Point { purpose: "combine", ge: PK::from(&result) }
    }

    fn sub_point(&self, other: &PK) -> Secp256k1Point {
        let result = self.ge.to_projective() + other.to_projective().neg();
        Secp256k1Point { purpose: "sub", ge: PK::from(&result) }
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Secp256k1Point {
        let mut vec_x = BigInt::to_vec(x);
        let mut vec_y = BigInt::to_vec(y);
        if vec_x.len() < 32 {
            let mut buf = vec![0; 32 - vec_x.len()]; buf.extend_from_slice(&vec_x); vec_x = buf;
        }
        if vec_y.len() < 32 {
            let mut buf = vec![0; 32 - vec_y.len()]; buf.extend_from_slice(&vec_y); vec_y = buf;
        }
        assert_eq!(x, &BigInt::from(vec_x.as_ref()));
        assert_eq!(y, &BigInt::from(vec_y.as_ref()));
        let mut v = vec![4u8];
        v.extend(vec_x);
        v.extend(vec_y);
        Secp256k1Point { purpose: "from_coor", ge: PK::from_slice(&v).unwrap() }
    }
}

// Point operator impls provide `point * scalar` and `point + point` syntax.

impl Mul<Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: Secp256k1Scalar) -> Self::Output { self.scalar_mul(&other.get_element()) }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output { self.scalar_mul(&other.get_element()) }
}

impl<'o> Mul<&'o Secp256k1Scalar> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output { self.scalar_mul(&other.get_element()) }
}

impl Add<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: Secp256k1Point) -> Self::Output { self.add_point(&other.get_element()) }
}

impl<'o> Add<&'o Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output { self.add_point(&other.get_element()) }
}

impl<'o> Add<&'o Secp256k1Point> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output { self.add_point(&other.get_element()) }
}

// Point serde ({x, y} hex object format, matching the secp256k1 backend)

impl Serialize for Secp256k1Point {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.x_coor().unwrap().to_hex())?;
        state.serialize_field("y", &self.y_coor().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Secp256k1Point {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct("Secp256k1Point", &["x", "y"], Secp256k1PointVisitor)
    }
}

struct Secp256k1PointVisitor;

impl<'de> Visitor<'de> for Secp256k1PointVisitor {
    type Value = Secp256k1Point;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("{x, y} hex") }
    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Secp256k1Point, E::Error> {
        let mut x = String::new();
        let mut y = String::new();
        while let Some(ref key) = map.next_key::<String>()? {
            let v = map.next_value::<String>()?;
            match key.as_str() { "x" => x = v, "y" => y = v, _ => panic!("Bad field") }
        }
        Ok(Secp256k1Point::from_coor(&BigInt::from_hex(&x), &BigInt::from_hex(&y)))
    }
}

// ============ Tests ============

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curv::arithmetic::traits::{Converter, Modulo};
    use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};

    #[test]
    fn serialize_sk() {
        let scalar: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));
        assert_eq!(serde_json::to_string(&scalar).unwrap(), "\"1e240\"");
    }

    #[test]
    fn deserialize_sk() {
        let dummy: Secp256k1Scalar = serde_json::from_str("\"1e240\"").unwrap();
        let sk: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));
        assert_eq!(dummy, sk);
    }

    #[test]
    fn serialize_pk() {
        let pk = Secp256k1Point::generator();
        let s = serde_json::to_string(&pk).unwrap();
        let expected = format!("{{\"x\":\"{}\",\"y\":\"{}\"}}", pk.x_coor().unwrap().to_hex(), pk.y_coor().unwrap().to_hex());
        assert_eq!(s, expected);
        assert_eq!(serde_json::from_str::<Secp256k1Point>(&s).unwrap().ge, pk.ge);
    }

    #[test]
    fn test_serdes_pk() {
        for pk in [GE::generator(), GE::base_point2()] {
            let s = serde_json::to_string(&pk).unwrap();
            assert_eq!(serde_json::from_str::<GE>(&s).unwrap(), pk);
        }
    }

    #[test]
    #[should_panic]
    fn test_serdes_bad_pk() {
        let s = serde_json::to_string(&GE::generator()).unwrap().replace("79be", "79bf");
        let _: GE = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn test_from_bytes() {
        let g = Secp256k1Point::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        assert!(Secp256k1Point::from_bytes(&BigInt::to_vec(&hash)).is_err());
    }

    #[test]
    fn test_from_bytes_2() {
        let g: Secp256k1Point = ECPoint::generator();
        let h = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let h = HSha256::create_hash(&[&h]);
        let h = HSha256::create_hash(&[&h]);
        assert_eq!(Secp256k1Point::from_bytes(&BigInt::to_vec(&h)).unwrap(), Secp256k1Point::base_point2());
    }

    #[test]
    fn test_point_subtraction() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let order = FE::q();
        let a_minus_b: FE = ECScalar::from(&BigInt::mod_add(
            &a.to_big_int(),
            &BigInt::mod_sub(&order, &b.to_big_int(), &order),
            &order,
        ));
        let base: GE = ECPoint::generator();
        assert_eq!((base * a_minus_b).ge, (base * a).sub_point(&(base * b).ge).ge);
    }

    #[test]
    fn test_invert() {
        let a: FE = ECScalar::new_random();
        assert_eq!(a.to_big_int().invert(&FE::q()).unwrap(), a.invert().to_big_int());
    }

    #[test]
    fn test_scalar_mul_scalar() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        assert_eq!(ECScalar::mul(&a, &b.get_element()).fe, (a * b).fe);
    }

    #[test]
    fn test_pad_coordinates() {
        let vx = BigInt::from_hex("ccaf75ab7960a01eb421c0e2705f6e84585bd0a094eb6af928c892a4a2912508");
        let vy = BigInt::from_hex("e788e294bd64eee6a73d2fc966897a31eb370b7e8e9393b0d8f4f820b48048df");
        Secp256k1Point::from_coor(&vx, &vy);

        let x = BigInt::from_hex("5f6853305467a385b56a5d87f382abb52d10835a365ec265ce510e04b3c3366f");
        let y = BigInt::from_hex("b868891567ca1ee8c44706c0dc190dd7779fe6f9b92ced909ad870800451e3");
        Secp256k1Point::from_coor(&x, &y); // y < 32 bytes, needs padding

        let r = Secp256k1Point::random_point();
        let r2 = Secp256k1Point::from_coor(&r.x_coor().unwrap(), &r.y_coor().unwrap());
        assert_eq!(r.x_coor().unwrap(), r2.x_coor().unwrap());
    }
}
