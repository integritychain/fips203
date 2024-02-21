use criterion::{criterion_group, criterion_main, Criterion};
use fips203::traits::{Decaps, Encaps, KeyGen};
use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};


#[allow(clippy::redundant_closure)]
pub fn criterion_benchmark(c: &mut Criterion) {
    let (ek_512, dk_512) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (_, ct_512) = ek_512.try_encaps_vt().unwrap();
    let (ek_768, dk_768) = ml_kem_768::KG::try_keygen_vt().unwrap();
    let (_, ct_768) = ek_768.try_encaps_vt().unwrap();
    let (ek_1024, dk_1024) = ml_kem_1024::KG::try_keygen_vt().unwrap();
    let (_, ct_1024) = ek_1024.try_encaps_vt().unwrap();

    c.bench_function("ml_kem_512  KeyGen", |b| b.iter(|| ml_kem_512::KG::try_keygen_vt()));
    c.bench_function("ml_kem_768  KeyGen", |b| b.iter(|| ml_kem_768::KG::try_keygen_vt()));
    c.bench_function("ml_kem_1024 KeyGen", |b| b.iter(|| ml_kem_1024::KG::try_keygen_vt()));

    c.bench_function("ml_kem_512  Encaps", |b| b.iter(|| ek_512.try_encaps_vt()));
    c.bench_function("ml_kem_768  Encaps", |b| b.iter(|| ek_768.try_encaps_vt()));
    c.bench_function("ml_kem_1024 Encaps", |b| b.iter(|| ek_1024.try_encaps_vt()));

    c.bench_function("ml_kem_512  Decaps", |b| b.iter(|| dk_512.try_decaps_vt(&ct_512)));
    c.bench_function("ml_kem_768  Decaps", |b| b.iter(|| dk_768.try_decaps_vt(&ct_768)));
    c.bench_function("ml_kem_1024 Decaps", |b| b.iter(|| dk_1024.try_decaps_vt(&ct_1024)));
}


criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
