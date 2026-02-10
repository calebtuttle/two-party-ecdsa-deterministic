// JS BigInt FFI glue for WASM.
// Called from big_js.rs via wasm-bindgen for hot-path modular arithmetic.
// Browser-native BigInt uses optimized C++ (V8/SpiderMonkey) — much faster
// than pure-Rust num-bigint compiled to WASM for large (2048-bit) operations.

export function js_mod_pow(base_hex, exp_hex, mod_hex) {
    const b = BigInt('0x' + (base_hex || '0'));
    const e = BigInt('0x' + (exp_hex || '0'));
    const m = BigInt('0x' + (mod_hex || '1'));
    if (m === 0n) return '0';
    let result = 1n;
    let base = ((b % m) + m) % m;
    let exp = e;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % m;
        exp >>= 1n;
        base = (base * base) % m;
    }
    return result.toString(16);
}

export function js_mod_mul(a_hex, b_hex, mod_hex) {
    const a = BigInt('0x' + (a_hex || '0'));
    const b = BigInt('0x' + (b_hex || '0'));
    const m = BigInt('0x' + (mod_hex || '1'));
    if (m === 0n) return '0';
    return (((a % m) * (b % m)) % m).toString(16);
}

export function js_mod_inv(a_hex, mod_hex) {
    let a = BigInt('0x' + (a_hex || '0'));
    const m = BigInt('0x' + (mod_hex || '1'));
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
