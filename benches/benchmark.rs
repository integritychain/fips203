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

$ export RUSTFLAGS="-C target-cpu=native"
$ cargo bench   # As of 1-7-24
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

ml_kem_512 KeyGen       time:   [35.738 µs 35.763 µs 35.788 µs]
ml_kem_768 KeyGen       time:   [59.768 µs 59.775 µs 59.782 µs]
ml_kem_1024 KeyGen      time:   [90.837 µs 90.844 µs 90.852 µs]

ml_kem_512 Encaps       time:   [37.941 µs 37.949 µs 37.956 µs]
ml_kem_768 Encaps       time:   [61.000 µs 61.017 µs 61.040 µs]
ml_kem_1024 Encaps      time:   [89.328 µs 89.369 µs 89.432 µs]

ml_kem_512 Decaps       time:   [49.490 µs 49.507 µs 49.523 µs]
ml_kem_768 Decaps       time:   [77.838 µs 78.019 µs 78.412 µs]
ml_kem_1024 Decaps      time:   [111.48 µs 111.49 µs 111.50 µs]

 */
