use criterion::{criterion_group, criterion_main, Criterion};
use rand::SeedableRng as _;
use ring_lwe::utils::{gen_uniform_poly, polymul, polymul_fast, Parameters};

fn benchmark_polymul_uniform(c: &mut Criterion) {
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let params = Parameters::default();
    let (n, q) = (params.n, params.q);

    // Input polynomials (padded to length `n`)
    let poly_0 = gen_uniform_poly(n, q, &mut rng);
    let poly_1 = gen_uniform_poly(n, q, &mut rng);

    // Time standard multiplication
    c.bench_function("Standard polymul (large)", |b| {
        b.iter(|| polymul(&poly_0, &poly_1, q, &params.f))
    });

    // Time fast multiplication
    c.bench_function("Fast polymul (large)", |b| {
        b.iter(|| polymul_fast(&poly_0, &poly_1, q, &params.ntt_plan))
    });
}

criterion_group!(benches, benchmark_polymul_uniform);
criterion_main!(benches);
