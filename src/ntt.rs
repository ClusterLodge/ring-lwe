pub type NttPlan = tfhe_ntt::prime64::Plan;

/// Forward NTT result.
///
/// Sometimes it can be cached to improve performance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fwd<N>(pub Vec<N>);

impl Fwd<u32> {
    /// We assume that x's elements are within centered q-range.
    pub fn new(x: &[i32], q: i32, ntt_plan: &tfhe_ntt::prime32::Plan) -> Self {
        let n = ntt_plan.ntt_size();

        // Pad coefficients
        let mut x_pad = Vec::with_capacity(n);
        x_pad.extend(x.iter().map(|&xi| {
            let c = if xi < 0 { xi + q } else { xi };
            c as u32
        }));
        x_pad.resize(n, 0);

        ntt_plan.fwd(&mut x_pad);
        Self(x_pad)
    }
}

impl Fwd<u64> {
    /// We assume that x's elements are within centered q-range.
    pub fn new(x: &[i64], q: i64, ntt_plan: &tfhe_ntt::prime64::Plan) -> Self {
        let n = ntt_plan.ntt_size();

        // Pad coefficients
        let mut x_pad = Vec::with_capacity(n);
        x_pad.extend(x.iter().map(|&xi| {
            let c = if xi < 0 { xi + q } else { xi };
            c as u64
        }));
        x_pad.resize(n, 0);

        ntt_plan.fwd(&mut x_pad);
        Self(x_pad)
    }
}
