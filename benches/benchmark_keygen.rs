use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::keygen::{keygen, keygen_bytes};
use ring_lwe::utils::{NttPlan, Parameters};

fn bench_keygen(c: &mut Criterion) {
    let params = Parameters::default();
    let ntt_plan = NttPlan::try_new(params.n, params.q as _).unwrap();
    c.bench_function("keygen", |b| b.iter(|| keygen(&params, None, &ntt_plan)));
}

fn bench_keygen_bytes(c: &mut Criterion) {
    let params = Parameters::default();

    c.bench_function("keygen_bytes", |b| b.iter(|| keygen_bytes(&params, None)));
}

criterion_group!(benches, bench_keygen, bench_keygen_bytes);
criterion_main!(benches);
