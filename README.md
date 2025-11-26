# Deterministic 2PC-ECDSA Signing Protocol (RFC6979)

This repository is a fork of [ZenGo-X/two-party-ecdsa](https://github.com/ZenGo-X/two-party-ecdsa), implementing a threshold ECDSA signature scheme between two parties (2PC – Two Party Computation) proposed by Y. Lindell.

## 🔄 Modifications

This fork introduces a **deterministic signing process**, in line with [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979), which specifies how to deterministically generate the ephemeral nonce `k` used in ECDSA signatures.  
The original ZenGo implementation uses randomized nonce generation; this fork replaces that with **deterministic nonce derivation**.

### ✅ Why RFC6979?

RFC 6979 improves the security of ECDSA signatures by:
- Avoiding reliance on secure randomness at signing time.
- Preventing vulnerabilities from biased or reused nonces (`k`).
- Ensuring that for a given message and private key, the generated signature is always the same.

This is especially relevant in **threshold or multi-party settings**, where securely generating and coordinating randomness can introduce complexity and additional risk.
This could also be relevant with use cases requiring deterministic signatures as for credentials computation.

---

## 🔧 Technical Modifications

The following changes have been made compared to the upstream ZenGo repository:

### 1. Deterministic `k` Generation (RFC6979)

- The `k` value (ephemeral nonce) used in ECDSA is now derived deterministically using HMAC-DRBG as specified in [RFC6979 Section 3.2](https://datatracker.ietf.org/doc/html/rfc6979#section-3.2).
- The nonce `k` is generated as a function of:
  - The secret signing share (private input).
  - The message to be signed.
- Each party derives their own `k` independently, ensuring consistency without interaction or shared randomness.

> For details, see the modified `k` derivation logic in:  
> [`src/party_one.rs`](./src/party_one.rs) and [`src/party_two.rs`](./src/party_two.rs)

---

### 2. Integration with `BigInt` and `Mpz`

- The message input (`BigInt`) is hashed and processed deterministically.
- Utility functions convert `Mpz` (used in `curv`) to byte slices and vice versa to interoperate with HMAC and hash functions.

---

### 3. New Test Cases

- Added test coverage to verify:
  - Deterministic output for repeated signatures of the same message.
  - Correct signature verification using the aggregated public key.

---

## 📚 References

- Lindell, Y. (2017). *Fast Secure Two-Party ECDSA Signing*  
  [https://eprint.iacr.org/2017/552](https://eprint.iacr.org/2017/552)

- ZenGo-X Original Implementation  
  [https://github.com/ZenGo-X/two-party-ecdsa](https://github.com/ZenGo-X/two-party-ecdsa)

- RFC 6979: *Deterministic Usage of the Digital Signature Algorithm (DSA) and ECDSA*  
  [https://datatracker.ietf.org/doc/html/rfc6979](https://datatracker.ietf.org/doc/html/rfc6979)

---

## 🚧 Limitations / Considerations

- Only the signing phase has been modified to follow RFC6979; key generation and other steps are unchanged.
- Assumes SHA-256 as the hash function (as used in RFC6979 and ZenGo’s original ECDSA implementation).
- Currently supports the `Secp256k1` curve.

---

## 🧪 Running Tests

```bash
cargo test
