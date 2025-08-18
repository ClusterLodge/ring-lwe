use criterion::{criterion_group, criterion_main, Criterion};
use rand_distr::Distribution;
use ring_lwe::utils::Parameters;

fn bench_distr_weighted_alias_index_new(c: &mut Criterion) {
    let params = Parameters::default();
    let weights: Vec<_> = (0..params.q).map(|idx| idx * idx).collect(); // not quite realistic
    c.bench_function("random WeightedAliasIndex::new", |b| {
        b.iter(|| rand_distr::weighted::WeightedAliasIndex::new(weights.clone()).unwrap())
    });
}

fn bench_distr_weighted_alias_index_gen(c: &mut Criterion) {
    let params = Parameters::default();
    let weights: Vec<_> = (0..params.q).map(|idx| idx * idx).collect(); // not quite realistic
    let gen = rand_distr::weighted::WeightedAliasIndex::new(weights.clone()).unwrap();
    // we use 8 times less data because it works with bytes, and we use normal
    // size for ternary because it is works with bits.
    let mut data = vec![0i64; params.n / 8];
    let mut rng = rand::rng();

    c.bench_function("random WeightedAliasIndex::sample", |b| {
        b.iter(|| {
            for item in &mut data {
                *item = gen.sample(&mut rng) as _;
            }
        })
    });
}

fn bench_distr_weighted_index_new(c: &mut Criterion) {
    let params = Parameters::default();
    let weights: Vec<_> = (0..params.q).map(|idx| idx * idx).collect(); // not quite realistic
    c.bench_function("random WeightedIndex::new", |b| {
        b.iter(|| rand_distr::weighted::WeightedIndex::new(weights.clone()).unwrap())
    });
}

fn bench_distr_weighted_index_gen(c: &mut Criterion) {
    let params = Parameters::default();
    let weights: Vec<_> = (0..params.q).map(|idx| idx * idx).collect(); // not quite realistic
    let gen = rand_distr::weighted::WeightedIndex::new(weights).unwrap();
    // we use 8 times less data because it works with bytes, and we use normal
    // size for ternary because it is works with bits.
    let mut data = vec![0i64; params.n / 8];
    let mut rng = rand::rng();

    c.bench_function("random WeightedIndex::sample", |b| {
        b.iter(|| {
            for item in &mut data {
                *item = gen.sample(&mut rng) as _;
            }
        })
    });
}

fn bench_distr_ternary(c: &mut Criterion) {
    use rand_distr::Uniform;

    let params = Parameters::default();
    let mut data = vec![0i64; params.n];
    let between = Uniform::new(-1, 2).unwrap();
    let mut rng = rand::rng();

    c.bench_function("random ternary::sample", |b| {
        b.iter(|| {
            for ci in &mut data {
                *ci = between.sample(&mut rng);
            }
        })
    });
}

criterion_group!(
    benches,
    bench_distr_weighted_alias_index_new,
    bench_distr_weighted_alias_index_gen,
    bench_distr_weighted_index_new,
    bench_distr_weighted_index_gen,
    bench_distr_ternary,
);
criterion_main!(benches);
