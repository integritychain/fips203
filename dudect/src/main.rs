use dudect_bencher::{BenchRng, Class, ctbench_main, CtRunner};
use fips203::ml_kem_512;
// Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen};
use rand_core::{CryptoRng, RngCore};

// Dummy RNG that supplies a constant (incremented) value when 'asked'
#[derive(Copy, Clone)]
struct DummyRng {
    value: u8,
}

impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, out: &mut [u8]) { out.iter_mut().for_each(|b| *b = self.value); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        self.value = self.value.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for DummyRng {}


fn full_flow(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let rng_left = DummyRng { value: 111 };
    let rng_right = DummyRng { value: 222 };

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut rng_refs = [&rng_right; ITERATIONS_OUTER];

    // Interleave left and right
    for i in (0..(ITERATIONS_OUTER)).step_by(2) {
        classes[i] = Class::Left;
        rng_refs[i] = &rng_left;
    }

    for (class, &rng_r) in classes.into_iter().zip(rng_refs.iter()) {
        runner.run_one(class, || {
            let mut rng = rng_r.clone();
            for _ in 0..ITERATIONS_INNER {
                let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
                let (ssk1, ct) = ek.try_encaps_with_rng_vt(&mut rng).unwrap();
                let ssk2 = dk.try_decaps_vt(&ct).unwrap();
                assert_eq!(ssk1, ssk2);
            }
        })
    }
}

ctbench_main!(full_flow);
