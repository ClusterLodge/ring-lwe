use crate::utils::{
    append_block, gen_ternary_poly, gen_uniform_poly, polyadd, polyinv, polymul_fast, Parameters,
};
use polynomial_ring::Polynomial;

/// Generate a public and secret key pair
/// # Arguments:
/// * `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
/// (public key, secret key)
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let (pk, sk) = ring_lwe::keygen::keygen(&params, None);
/// ```
pub fn keygen(params: &Parameters, seed: Option<u64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    //rename parameters
    let (n, q, f, omega) = (params.n, params.q, &params.f, params.omega);

    // Generate a public and secret key
    let sk = gen_ternary_poly(n, seed);
    let a = gen_uniform_poly(n, q, seed);
    let e = gen_ternary_poly(n, seed);
    let b = polyadd(
        &polymul_fast(&polyinv(&a, q), &sk, q, f, omega),
        &polyinv(&e, q),
        q,
        f,
    ); // b = -a*sk - e

    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}

pub struct PubKey(pub Vec<i64>);

pub struct SecKey(pub Vec<i64>);

pub struct KeyPair {
    pub public: PubKey,
    pub secret: SecKey,
}

/// Generate a public and secret key pair and return as a HashMap
/// # Arguments:
/// * `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
/// HashMap containing public and secret keys as base64 encoded strings
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let keys = ring_lwe::keygen::keygen_bytes(&params, None);
/// let pk_string = keys.public;
/// let sk_string = keys.secret;
/// ```
pub fn keygen_bytes(params: &Parameters, seed: Option<u64>) -> KeyPair {
    let (pk, sk) = keygen(params, seed);

    let mut pk_coeffs: Vec<i64> = Vec::with_capacity(2 * params.n);
    append_block(&mut pk_coeffs, pk[0].coeffs(), params.n);
    append_block(&mut pk_coeffs, pk[1].coeffs(), params.n);

    KeyPair {
        public: PubKey(pk_coeffs),
        secret: SecKey(sk.coeffs().to_vec()),
    }
}
