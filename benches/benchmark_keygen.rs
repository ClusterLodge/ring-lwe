use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::keygen::{keygen, keygen_bytes};
use ring_lwe::utils::Parameters;

fn bench_params(c: &mut Criterion) {
    c.bench_function("keygen", |b| b.iter(|| Parameters::default()));
}

fn bench_keygen(c: &mut Criterion) {
    let params = Parameters::default();
    c.bench_function("keygen", |b| b.iter(|| keygen(&params, None)));
}

fn bench_keygen_bytes(c: &mut Criterion) {
    let params = Parameters::default();

    c.bench_function("keygen_bytes", |b| b.iter(|| keygen_bytes(&params, None)));
}

criterion_group!(benches, bench_params, bench_keygen, bench_keygen_bytes);
criterion_main!(benches);
