use bincode;
use polynomial_ring::Polynomial;
use rand_distr::{Distribution, Normal, Uniform};

pub type NttPlan = tfhe_ntt::prime64::Plan;

/// Ring-LWE parameters
#[derive(Debug)]
pub struct Parameters {
    pub n: usize, // Polynomial modulus degree
    pub q: i64,   // Ciphertext modulus
    pub t: i64,   // Plaintext modulus
    pub ntt_plan: NttPlan,
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
    #[allow(dead_code)]
    pub sigma: f64, // Standard deviation for normal distribution
}

/// Default parameters for ring-LWE
impl Default for Parameters {
    fn default() -> Self {
        let n = 1024;
        let q = 12289i64;
        let t = 2;
        let ntt_plan = NttPlan::try_new(n, q as u64).expect("Failed to create NTT plan");
        let mut poly_vec = vec![0i64; n + 1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let sigma = 8.0;
        Parameters {
            n,
            q,
            t,
            ntt_plan,
            f,
            sigma,
        }
    }
}

/// Take remainder of the coefficients of a polynom by a given modulus
/// # Arguments:
/// * `x` - polynomial in Z[X]
/// * `modulus` - coefficient modulus
/// # Returns:
/// polynomial in Z_modulus[X]
pub fn mod_coeffs(x: Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    let coeffs = x.coeffs();
    if coeffs.is_empty() {
        // return original input for the zero polynomial
        x
    } else {
        let mut newcoeffs = Vec::with_capacity(coeffs.len());
        newcoeffs.extend(coeffs.iter().cloned().map(|coeff| {
            let mut c = coeff.rem_euclid(modulus);
            if c > modulus / 2 {
                c -= modulus;
            }
            c
        }));
        Polynomial::new(newcoeffs)
    }
}

/// Polynomial remainder of x modulo f assuming f=x^n+1
/// # Arguments:
/// * `x` - polynomial in Z[X]
/// * `f` - polynomial modulus
/// # Returns:
/// polynomial in Z[X]/(f)
pub fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
    let n = f.coeffs().len() - 1;
    let mut coeffs = x.coeffs().to_vec();
    if coeffs.len() < n + 1 {
        Polynomial::new(coeffs)
    } else {
        for i in n..coeffs.len() {
            coeffs[i % n] += (-1_i64).pow((i / n).try_into().unwrap()) * coeffs[i];
        }
        coeffs.resize(n, 0);
        Polynomial::new(coeffs)
    }
}

/// Multiply two polynomials
/// # Arguments:
/// * `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `modulus` - coefficient modulus.
/// * `f` - polynomial modulus.
/// # Returns:
/// polynomial in Z_q[X]/(f)
#[allow(dead_code)]
pub fn polymul(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    q: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    let mut r = x * y;
    r = polyrem(r, f);
    if q != 0 {
        mod_coeffs(r, q)
    } else {
        r
    }
}

/// Multiply two polynomials using fast NTT algorithm
/// # Arguments:
/// * `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `q` - coefficient modulus.
/// * `f` - polynomial modulus.
/// * `omega` - n-th root of unity
/// # Returns:
/// polynomial in Z_q[X]/(f)
/// # Example:
/// ```
/// let p: i64 = 17; // Prime modulus
/// let n: usize = 8;  // Length of the NTT (must be a power of 2)
/// let omega = ntt::omega(p, n); // n-th root of unity
/// let params = ring_lwe::utils::Parameters::default();
/// let a = polynomial_ring::Polynomial::new(vec![1, 2, 3, 4]);
/// let b = polynomial_ring::Polynomial::new(vec![5, 6, 7, 8]);
/// let c_std = ring_lwe::utils::polymul(&a, &b, p, &params.f);
/// let c_fast = ring_lwe::utils::polymul_fast(&a, &b, p, &ntt_plan);
/// assert_eq!(c_std, c_fast, "test failed: {} != {}", c_std, c_fast);
/// ```
pub fn polymul_fast(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    q: i64,
    ntt_plan: &NttPlan,
) -> Polynomial<i64> {
    let n1 = x.coeffs().len();
    let n2 = y.coeffs().len();
    // Compute the nearest power of the max of input degrees+1
    // TODO it should be just plan's length; it just happens to work most of the time
    let n = std::cmp::max(n1, n2).next_power_of_two();
    // Pad coefficients
    let x_pad = {
        let mut coeffs = Vec::with_capacity(n);
        coeffs.extend(x.coeffs().iter().cloned());
        coeffs.resize(n, 0);
        coeffs
    };
    let y_pad = {
        let mut coeffs = Vec::with_capacity(n);
        coeffs.extend(y.coeffs().iter().cloned());
        coeffs.resize(n, 0);
        coeffs
    };

    // Perform the polynomial multiplication
    let r_coeffs = polymul_ntt(&x_pad, &y_pad, q, ntt_plan);

    // Construct the result polynomial and reduce modulo f
    let r = Polynomial::new(r_coeffs);
    // let r = polyrem(r, f);
    mod_coeffs(r, q)
}

fn polymul_ntt(x: &[i64], y: &[i64], q: i64, ntt_plan: &NttPlan) -> Vec<i64> {
    let mut x1 = x
        .iter()
        .map(|&c| (if c < 0 { c + q } else { c }) as _)
        .collect::<Vec<_>>();
    let mut y1 = y
        .iter()
        .map(|&c| (if c < 0 { c + q } else { c }) as _)
        .collect::<Vec<_>>();

    ntt_plan.fwd(&mut x1);
    ntt_plan.fwd(&mut y1);
    ntt_plan.mul_assign_normalize(&mut x1, &y1);
    ntt_plan.inv(&mut x1);

    x1.into_iter().map(|c| c as i64).collect::<Vec<_>>()
}

/// Add two polynomials
/// # Arguments:
/// * `x` - polynomial to be added
/// * `y` - polynomial to be added.
/// * `modulus` - coefficient modulus.
/// * `f` - polynomial modulus.
/// # Returns:
/// polynomial in Z_modulus[X]/(f)
pub fn polyadd(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    modulus: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    let mut r = x + y;
    r = polyrem(r, f);
    if modulus != 0 {
        mod_coeffs(r, modulus)
    } else {
        r
    }
}

/// Additive inverse of a polynomial
/// # Arguments:
/// * `x` - polynomial to be inverted
/// * `modulus` - coefficient modulus.
/// # Returns:
/// polynomial in Z_modulus[X]
pub fn polyinv(x: &Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    //Additive inverse of polynomial x modulo modulus
    let y = -x;
    if modulus != 0 {
        mod_coeffs(y, modulus)
    } else {
        y
    }
}

/// Subtract two polynomials
/// # Arguments:
/// * `x` - polynomial to be subtracted
/// * `y` - polynomial to be subtracted.
/// * `modulus` - coefficient modulus.
/// * `f` - polynomial modulus.
/// # Returns:
/// polynomial in Z_modulus[X]/(f)
#[allow(dead_code)]
pub fn polysub(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    modulus: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    polyadd(x, &polyinv(y, modulus), modulus, f)
}

/// Generate a binary polynomial
/// # Arguments:
/// * `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
/// polynomial in Z_modulus[X]/(f) with coefficients in {0,1}
#[allow(dead_code)]
pub fn gen_binary_poly<Rng: rand::Rng>(size: usize, rng: &mut Rng) -> Polynomial<i64> {
    let between = Uniform::new(0, 2).unwrap();
    let mut coeffs = vec![0i64; size];
    for ci in &mut coeffs {
        *ci = between.sample(rng);
    }
    Polynomial::new(coeffs)
}

/// Generate a ternary polynomial
/// # Arguments:
/// * `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
/// ternary polynomial with coefficients in {-1,0,+1}
pub fn gen_ternary_poly<Rng: rand::Rng>(size: usize, rng: &mut Rng) -> Polynomial<i64> {
    let between = Uniform::new(-1, 2).unwrap();
    let mut coeffs = vec![0i64; size];
    for ci in &mut coeffs {
        *ci = between.sample(rng);
    }
    Polynomial::new(coeffs)
}

/// Generate a uniform polynomial
/// # Arguments:
/// * `size` - number of coefficients
/// * `q` - coefficient modulus
/// * `seed` - random seed
/// # Returns:
/// uniform polynomial with coefficients in {0,1,...,q-1}
pub fn gen_uniform_poly<Rng: rand::Rng>(size: usize, q: i64, rng: &mut Rng) -> Polynomial<i64> {
    let between = Uniform::new(0, q).unwrap();
    let mut coeffs = vec![0i64; size];
    for ci in &mut coeffs {
        *ci = between.sample(rng);
    }
    mod_coeffs(Polynomial::new(coeffs), q)
}

/// Generate a normal polynomial
/// # Arguments:
/// * `size` - number of coefficients
/// * `sigma` - standard deviation
/// * `seed` - random seed
/// # Returns:
/// polynomial with coefficients sampled from a normal distribution
#[allow(dead_code)]
pub fn gen_normal_poly<Rng: rand::Rng>(size: usize, sigma: f64, rng: &mut Rng) -> Polynomial<i64> {
    let normal = Normal::new(0.0_f64, sigma).unwrap();
    let mut coeffs = vec![0i64; size];
    for ci in &mut coeffs {
        *ci = normal.sample(rng).round() as i64;
    }
    Polynomial::new(coeffs)
}

/// nearest integer to the ratio a/b
/// # Arguments:
/// * `a` - numerator
/// * `b` - denominator
/// # Returns:
/// nearest integer to the ratio a/b
pub fn nearest_int(a: i64, b: i64) -> i64 {
    if a > 0 {
        (a + b / 2) / b
    } else {
        -((-a + b / 2) / b)
    }
}

/// seralize and encode a vector of i64 to a bincode encoded vector
/// # Arguments
/// * `data` - vector of i64
/// # Returns
/// * `encoded` - bincode encoded vector
pub fn compress(data: &Vec<i64>) -> Vec<u8> {
    bincode::serialize(data).expect("Failed to serialize data")
}

/// decode and deserialize a bincode encoded vector to a vector of i64
/// # Arguments
/// * `bincode_bytes` - base64 encoded string
/// # Returns
/// * `decoded_data` - vector of i64
pub fn decompress(bincode_bytes: &[u8]) -> Vec<i64> {
    bincode::deserialize(bincode_bytes).expect("Failed to deserialize data")
}

pub(crate) fn append_block<T: Clone + Default>(buff: &mut Vec<T>, data: &[T], n: usize) {
    assert!(
        data.len() <= n,
        "Data length exceeds block size: {}",
        data.len()
    );
    buff.extend_from_slice(data);
    for _ in data.len()..n {
        buff.push(T::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() {
        let ntt_plan = NttPlan::try_new(1024, 12289).expect("Failed to create NTT plan");
        const N: usize = 1024;
        let mut p1 = vec![-8];
        let mut p2 = vec![-8];

        p1.resize(N, 0);
        p2.resize(N, 0);
        let r = polymul_ntt(&p1, &p2, 12289, &ntt_plan);
        let r = Polynomial::new(r);
        assert_eq!(r.coeffs(), vec![64])
    }
}
