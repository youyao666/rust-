use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_example(c: &mut Criterion) {
    c.bench_function("example", |b| {
        b.iter(|| {
            let data = vec![0u8; 1024];
            black_box(data);
        })
    });
}

criterion_group!(benches, benchmark_example);
criterion_main!(benches);
