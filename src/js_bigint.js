// JS BigInt FFI glue for WASM.
// Called from big_js.rs via wasm-bindgen for hot-path modular arithmetic.
// Browser-native BigInt uses optimized C++ (V8/SpiderMonkey) — much faster
// than pure-Rust num-bigint compiled to WASM for large (2048-bit) operations.

// num_bigint's to_str_radix(16) emits "-abc" for negatives (sign before hex
// digits, no 0x prefix).  Naively doing BigInt('0x' + s) produces the invalid
// literal "0x-abc".  This helper puts the sign before the 0x prefix.
function fromHex(h) {
    if (!h || h === '0') return 0n;
    if (h[0] === '-') return -BigInt('0x' + h.slice(1));
    return BigInt('0x' + h);
}

export function js_mod_pow(base_hex, exp_hex, mod_hex) {
    const b = fromHex(base_hex);
    const e = fromHex(exp_hex);
    const m = fromHex(mod_hex) || 1n;
    if (m === 0n) return '0';
    let result = 1n;
    let result2 = 1n;
    let base = ((b % m) + m) % m;
    let exp = e;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % m;
        else result2 = (result2 * base) % m;
        exp >>= 1n;
        base = (base * base) % m;
    }
    return result.toString(16);
}

export function js_mod_mul(a_hex, b_hex, mod_hex) {
    const a = fromHex(a_hex);
    const b = fromHex(b_hex);
    const m = fromHex(mod_hex) || 1n;
    if (m === 0n) return '0';
    // JS % can return negative — normalize with (x % m + m) % m
    const am = ((a % m) + m) % m;
    const bm = ((b % m) + m) % m;
    return ((am * bm) % m).toString(16);
}

export function js_mod_inv(a_hex, mod_hex) {
    let a = fromHex(a_hex);
    const m = fromHex(mod_hex) || 1n;
    if (m === 0n) return '0';
    a = ((a % m) + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m + m) % m).toString(16);
}
