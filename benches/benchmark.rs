use criterion::{Criterion, criterion_group, criterion_main};

use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};
use fips203::traits::{Decaps, Encaps, KeyGen};

#[allow(clippy::redundant_closure)]
pub fn criterion_benchmark(c: &mut Criterion) {
    let (ek_512, dk_512) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (_, ct_512) = ek_512.try_encaps_vt().unwrap();
    let (ek_768, dk_768) = ml_kem_768::KG::try_keygen_vt().unwrap();
    let (_, ct_768) = ek_768.try_encaps_vt().unwrap();
    let (ek_1024, dk_1024) = ml_kem_1024::KG::try_keygen_vt().unwrap();
    let (_, ct_1024) = ek_1024.try_encaps_vt().unwrap();

    c.bench_function("ml_kem_512 KeyGen", |b| b.iter(|| ml_kem_512::KG::try_keygen_vt()));
    c.bench_function("ml_kem_512 Encaps", |b| b.iter(|| ek_512.try_encaps_vt()));
    c.bench_function("ml_kem_512 Decaps", |b| b.iter(|| dk_512.try_decaps_vt(&ct_512)));

    c.bench_function("ml_kem_768 KeyGen", |b| b.iter(|| ml_kem_768::KG::try_keygen_vt()));
    c.bench_function("ml_kem_768 Encaps", |b| b.iter(|| ek_768.try_encaps_vt()));
    c.bench_function("ml_kem_768 Decaps", |b| b.iter(|| dk_768.try_decaps_vt(&ct_768)));

    c.bench_function("ml_kem_1024 KeyGen", |b| b.iter(|| ml_kem_1024::KG::try_keygen_vt()));
    c.bench_function("ml_kem_1024 Encaps", |b| b.iter(|| ek_1024.try_encaps_vt()));
    c.bench_function("ml_kem_1024 Decaps", |b| b.iter(|| dk_1024.try_decaps_vt(&ct_1024)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

/*

$ cargo bench   # As of 1-6-24
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

ml_kem_512 KeyGen       time:   [38.781 µs 39.282 µs 39.905 µs]
ml_kem_768 KeyGen       time:   [64.254 µs 64.558 µs 65.107 µs]
ml_kem_1024 KeyGen      time:   [100.13 µs 100.80 µs 101.55 µs]

ml_kem_512 Encaps       time:   [43.175 µs 43.851 µs 44.658 µs]
ml_kem_768 Encaps       time:   [68.038 µs 68.808 µs 69.817 µs]
ml_kem_1024 Encaps      time:   [102.59 µs 102.95 µs 103.34 µs]

ml_kem_512 Decaps       time:   [54.167 µs 54.810 µs 55.564 µs]
ml_kem_768 Decaps       time:   [84.112 µs 85.940 µs 87.994 µs]
ml_kem_1024 Decaps      time:   [121.48 µs 122.99 µs 125.10 µs]

 */
