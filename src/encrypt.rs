use crate::{
    keygen::PubKey,
    utils::{
        append_block, compress, gen_ternary_poly, mod_coeffs, polyadd, polymul_fast, Parameters,
    },
};
use itertools::Itertools as _;
use polynomial_ring::Polynomial;

/// Encrypt a polynomial using the public key
/// # Arguments:
/// * `pk` - public key as an array of two Polynomials
/// * `m` - plaintext polynomial
/// * `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
/// (ciphertext component 0, ciphertext component 1)
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let (pk, sk) = ring_lwe::keygen::keygen(&params, None);
/// let m = polynomial_ring::Polynomial::new(vec![1, 0, 1]);
/// let ct = ring_lwe::encrypt::encrypt(&pk, &m, &params, None);
/// ```
pub fn encrypt(
    pk: &[Polynomial<i64>; 2], // Public key (b, a)
    m: &Polynomial<i64>,       // Plaintext polynomial
    params: &Parameters,       //parameters (n,q,t,f)
    seed: Option<u64>,         // Seed for random number generator
) -> [Polynomial<i64>; 2] {
    let (n, q, t, f, ntt_plan) = (params.n, params.q, params.t, &params.f, &params.ntt_plan);
    // Scale the plaintext polynomial. use floor(m*q/t) rather than floor (q/t)*m
    let scaled_m = mod_coeffs(m * q / t, q);

    // Generate random polynomials
    let e1 = gen_ternary_poly(n, seed);
    let e2 = gen_ternary_poly(n, seed);
    let u = gen_ternary_poly(n, seed);

    // Compute ciphertext components
    let ct0 = polyadd(
        &polyadd(&polymul_fast(&pk[0], &u, q, ntt_plan), &e1, q, f),
        &scaled_m,
        q,
        f,
    );
    let ct1 = polyadd(&polymul_fast(&pk[1], &u, q, ntt_plan), &e2, q, f);

    [ct0, ct1]
}

/// Encrypt bytes or string using the public key
/// # Arguments:
/// * `pk` - public key as a bincode encoded slice of bytes
/// * `message` - message to encrypt
/// * `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
/// encrypted message as a bincode encoded vector
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let keys = ring_lwe::keygen::keygen_bytes(&params, None);
/// let pk = keys.public;
/// let message = "hello".as_bytes();
/// let ciphertext = ring_lwe::encrypt::encrypt_bytes(&pk, &message, &params, None);
/// ```
pub fn encrypt_bytes(
    pk: &PubKey,
    message: &[u8],
    params: &Parameters,
    seed: Option<u64>,
) -> Vec<u8> {
    // Decode the Base64 public key string
    let pk_arr = &pk.0;

    // Split the public key into two polynomials
    let pk_b = Polynomial::new(pk_arr[..params.n].to_vec());
    let pk_a = Polynomial::new(pk_arr[params.n..].to_vec());
    let pk = [pk_b, pk_a];

    // Convert each byte into its 8-bit representation (MSB first)
    let message_bits = message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1) as i64));

    let message_chunks = message_bits.chunks(params.n); // Pack bits into polynomials of size `n`
                                                        // Convert bits into a vector of Polynomials
    let message_blocks = message_chunks
        .into_iter()
        .map(|chunk| Polynomial::new(chunk.collect_vec()));

    // Encrypt each integer message block
    let mut ciphertext_list: Vec<i64> = Vec::new();
    for message_block in message_blocks {
        let ciphertext = encrypt(&pk, &message_block, params, seed);
        append_block(&mut ciphertext_list, ciphertext[0].coeffs(), params.n);
        append_block(&mut ciphertext_list, ciphertext[1].coeffs(), params.n);
    }

    // Serialize the ciphertext list to binary and encode as Base64
    compress(&ciphertext_list)
}
