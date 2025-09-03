use criterion::{Criterion, criterion_group, criterion_main};

fn allocate_vec() {
    let mut v = Vec::with_capacity(1024);
    for i in 0..1024 {
        v.push(i);
    }
    std::hint::black_box(v);
}

fn allocation_latency(c: &mut Criterion) {
    c.bench_function("vec_allocate", |b| b.iter(allocate_vec));
}

criterion_group!(benches, allocation_latency);
criterion_main!(benches);
