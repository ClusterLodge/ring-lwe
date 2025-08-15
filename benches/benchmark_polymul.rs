use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::utils::{gen_uniform_poly, polymul, polymul_fast, Parameters, NttPlan};

fn benchmark_polymul_uniform(c: &mut Criterion) {
    let seed = None; // Set the random seed
    let params = Parameters::default();
    let (n, q) = (params.n, params.q);
    let ntt_plan = NttPlan::try_new(n, q as _).unwrap();

    // Input polynomials (padded to length `n`)
    let poly_0 = gen_uniform_poly(n, q, seed);
    let poly_1 = gen_uniform_poly(n, q, seed);

    // Time standard multiplication
    c.bench_function("Standard polymul (large)", |b| {
        b.iter(|| polymul(&poly_0, &poly_1, q, &params.f))
    });

    // Time fast multiplication
    c.bench_function("Fast polymul (large)", |b| {
        b.iter(|| polymul_fast(&poly_0, &poly_1, q, &ntt_plan))
    });
}

criterion_group!(benches, benchmark_polymul_uniform);
criterion_main!(benches);
