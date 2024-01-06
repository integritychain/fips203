// Note that this package does not provide any constant-time assurances.
// However, this code fragment lays the groundwork should that change.

use dudect_bencher::{BenchRng, Class, ctbench_main, CtRunner};
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen};

// Could also be ml_kem_768 or ml_kem_1024.
use crate::ml_kem_512::{CipherText, DecapsKey, EncapsKey};

fn encaps(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 1000;
    const ITERATIONS_INNER: usize = 100;

    let (ek1, _dk1) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (ek2, _dk2) = ml_kem_512::KG::try_keygen_vt().unwrap();

    let mut inputs: Vec<EncapsKey> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(ek1.clone());
        classes.push(Class::Left);
    }

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(ek2.clone());
        classes.push(Class::Right);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let _ = input.try_encaps_vt();
            }
        })
    }
}

fn decaps(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 1000;
    const ITERATIONS_INNER: usize = 100;

    let (ek1, dk1) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (_ssk, ct1) = ek1.try_encaps_vt().unwrap();
    let (ek2, dk2) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (_ssk, ct2) = ek2.try_encaps_vt().unwrap();

    let mut inputs: Vec<(DecapsKey, CipherText)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS_OUTER {
        inputs.push((dk1.clone(), ct1.clone()));
        classes.push(Class::Left);
    }

    for _ in 0..ITERATIONS_OUTER {
        inputs.push((dk2.clone(), ct2.clone()));
        classes.push(Class::Right);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let _ = input.0.try_decaps_vt(&input.1);
            }
        })
    }
}


ctbench_main!(encaps, decaps);

/*
See https://docs.rs/dudect-bencher/latest/dudect_bencher/

$ cargo run --release -- --continuous encaps
running 1 benchmark continuously
bench encaps seeded with 0xa533680b600ee91d
bench encaps ... : n == +0.002M, max t = +20.90838, max tau = +0.46953, (5/tau)^2 = 113
bench encaps ... : n == +0.003M, max t = +12.90667, max tau = +0.23820, (5/tau)^2 = 440
bench encaps ... : n == +0.004M, max t = +11.03463, max tau = +0.17258, (5/tau)^2 = 839
bench encaps ... : n == +0.003M, max t = +14.12761, max tau = +0.25057, (5/tau)^2 = 398
bench encaps ... ^C: n == +0.004M, max t = +13.49987, max tau = +0.21857, (5/tau)^2 = 523

cargo run --release -- --continuous decaps
running 1 benchmark continuously
bench decaps seeded with 0x0cd3626e7d56f68c
bench decaps ... : n == +0.002M, max t = +7.38286, max tau = +0.18856, (5/tau)^2 = 703
bench decaps ... : n == +0.003M, max t = +11.21373, max tau = +0.19150, (5/tau)^2 = 681
bench decaps ... : n == +0.006M, max t = +38.99984, max tau = +0.50765, (5/tau)^2 = 97
bench decaps ... : n == +0.008M, max t = +29.45174, max tau = +0.33622, (5/tau)^2 = 221

*/