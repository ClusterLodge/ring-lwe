use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::keygen::{keygen, keygen_bytes};
use ring_lwe::utils::Parameters;
use rand::SeedableRng as _;

fn bench_params(c: &mut Criterion) {
    c.bench_function("params", |b| b.iter(|| Parameters::default()));
}

fn bench_keygen(c: &mut Criterion) {
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let params = Parameters::default();
    c.bench_function("keygen", |b| b.iter(|| keygen(&params, &mut rng)));
}

fn bench_keygen_bytes(c: &mut Criterion) {
    let params = Parameters::default();

    c.bench_function("keygen_bytes", |b| b.iter(|| keygen_bytes(&params)));
}

criterion_group!(benches, bench_params, bench_keygen, bench_keygen_bytes);
criterion_main!(benches);
