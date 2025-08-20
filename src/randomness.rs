use polynomial_ring::Polynomial;
use rand::Rng;

pub(crate) fn cbinomial<const BITS: u32, const BATCH: u32, Dst: From<i32>>(
    dst: &mut Vec<Dst>,
    rng: &mut impl Rng,
) {
    assert!(BITS * BATCH <= 64);
    let left = rng.next_u64();
    let right = rng.next_u64();

    let summation_mask = (0..BATCH)
        .map(|group_id| 1 << (BITS * group_id))
        .fold(0, |a, b| a | b);

    let left_bits = (0..BITS)
        .map(|offset| (left >> offset) & summation_mask)
        .sum::<u64>();
    let right_bits = (0..BITS)
        .map(|offset| (right >> offset) & summation_mask)
        .sum::<u64>();

    let group_mask = (1 << BITS) - 1;
    for group_id in 0..BATCH {
        let l = (left_bits >> (BITS * group_id)) & group_mask;
        let r = (right_bits >> (BITS * group_id)) & group_mask;
        let val = (l as i32) - (r as i32);
        dst.push(val.into());
    }
}

/// Generate a noise polynomial
/// # Arguments:
/// * `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
/// noise polynomial with cbinomial distribution
pub fn gen_noise_poly(size: usize, rng: &mut impl Rng) -> Polynomial<i64> {
    let mut coeffs = Vec::with_capacity(size);
    while coeffs.len() < size {
        cbinomial::<2, 32, _>(&mut coeffs, rng);
    }
    coeffs.truncate(size);
    // coeffs.fill(0);   // STUB for debug
    Polynomial::new(coeffs)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand_distr::Distribution;

    use super::*;

    #[test]
    #[ignore]
    fn debug_cbinom() {
        let mut dst = Vec::<i32>::with_capacity(128);
        let mut rng = rand::rng();
        cbinomial::<2, 32, i32>(&mut dst, &mut rng);
        cbinomial::<2, 32, i32>(&mut dst, &mut rng);
        cbinomial::<2, 32, i32>(&mut dst, &mut rng);
        cbinomial::<2, 32, i32>(&mut dst, &mut rng);

        let mut dist = BTreeMap::<_, usize>::new();
        for k in dst {
            *dist.entry(k).or_default() += 1;
        }

        // always fails, but it is a good way to see dist.
        assert_eq!(dist, BTreeMap::new());
    }

    #[test]
    #[ignore]
    fn debug_ternary() {
        use rand_distr::Uniform;

        let between = Uniform::new(-1, 2).unwrap();
        let mut dst = Vec::<i32>::with_capacity(128);
        let mut rng = rand::rng();
        for _ in 0..128 {
            dst.push(between.sample(&mut rng))
        }

        let mut dist = BTreeMap::<_, usize>::new();
        for k in dst {
            *dist.entry(k).or_default() += 1;
        }

        // always fails, but it is a good way to see dist.
        assert_eq!(dist, BTreeMap::new());
    }
}
