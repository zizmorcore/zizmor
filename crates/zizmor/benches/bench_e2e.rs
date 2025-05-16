use criterion::{Criterion, criterion_group, criterion_main};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("stub", |b| b.iter(|| todo!()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
