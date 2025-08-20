use crate::{
    keygen::SecKey,
    ntt::Fwd,
    utils::{decompress, nearest_int, polyadd, polymul_fast2, Parameters},
};
use polynomial_ring::Polynomial;

/// Decrypt a ciphertext using the secret key
/// # Arguments:
/// * `sk` - secret key
/// * `ct` - array of ciphertext polynomials
/// * `params` - ring-LWE parameters
/// # Returns:
/// decrypted polynomial
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let (pk, sk) = ring_lwe::keygen::keygen(&params, None);
/// let m = polynomial_ring::Polynomial::new(vec![1, 0, 1]);
/// let ct = ring_lwe::encrypt::encrypt(&pk, &m, &params, None);
/// let decrypted_m = ring_lwe::decrypt::decrypt(&sk, &ct, &params);
/// ```
pub fn decrypt(
    sk_fwd: Fwd<u64>,          // Secret key
    ct: &[Polynomial<i64>; 2], // Array of ciphertext polynomials
    params: &Parameters,
) -> Polynomial<i64> {
    let (_n, q, t, f) = (params.n, params.q, params.t, &params.f);
    let scaled_pt = polyadd(
        &polymul_fast2(sk_fwd, &ct[1], q, &params.ntt_plan),
        &ct[0],
        q,
        f,
    );
    let mut decrypted_coeffs = Vec::with_capacity(scaled_pt.coeffs().len());
    for c in scaled_pt.coeffs().iter() {
        let s = nearest_int(c * t, q);
        decrypted_coeffs.push(if t == 2 { s & 1 } else { s.rem_euclid(t) });
    }
    Polynomial::new(decrypted_coeffs)
}

/// Decrypt a ciphertext string using the secret key
/// # Arguments:
/// * `sk_string` - secret key as a base64 encoded string
/// * `ciphertext` - ciphertext to decrypt as a bincode encoded slice of bytes
/// * `params` - ring-LWE parameters
/// # Returns:
/// decrypted plaintext message
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let keys = ring_lwe::keygen::keygen_bytes(&params, None);
/// let sk = keys.secret;
/// let pk = keys.public;
/// let message = "hello".as_bytes();
/// let ciphertext = ring_lwe::encrypt::encrypt_bytes(&pk, &message, &params, None);
/// let decrypted_message = ring_lwe::decrypt::decrypt_bytes(&sk, &ciphertext, &params);
/// ```
pub fn decrypt_bytes(sk: &SecKey, ciphertext: &[u8], params: &Parameters) -> Vec<u8> {
    // Decode the base64 secret key string and deserialize into a vector of i64 coefficients
    let sk = Polynomial::new(sk.0.clone());

    let (q, ntt_plan) = (params.q, &params.ntt_plan);
    let sk_fwd = Fwd::<u64>::new(sk.coeffs(), q, ntt_plan);

    // Decode the Base64 ciphertext string and deserialize into vector of i32 coefficients
    let ciphertext_array: Vec<i64> = decompress(ciphertext);

    let num_blocks = ciphertext_array.len() / (2 * params.n);
    let mut decrypted_nibbles: Vec<i64> = Vec::new();

    for i in 0..num_blocks {
        let c0 =
            Polynomial::new(ciphertext_array[2 * i * params.n..(2 * i + 1) * params.n].to_vec());
        let c1 = Polynomial::new(
            ciphertext_array[(2 * i + 1) * params.n..(2 * i + 2) * params.n].to_vec(),
        );
        let ct = [c0, c1];

        // Decrypt the ciphertext
        decrypted_nibbles.extend(decrypt(sk_fwd.clone(), &ct, params).coeffs());
    }

    // Convert decrypted bits into a string
    let decrypted_message: Vec<u8> = decrypted_nibbles
        .chunks(2)
        .map(|byte| {
            let bit_str: u8 = byte
                .iter()
                .enumerate()
                .map(|(idx, &b)| ((b as u8) << ((idx * 4) as u32)))
                .sum();
            bit_str
        })
        .collect();

    decrypted_message
}
