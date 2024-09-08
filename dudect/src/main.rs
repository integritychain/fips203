use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen};
use rand_core::{CryptoRng, RngCore};


// Simplistic RNG to regurgitate set value
#[derive(Clone)]
struct TestRng([u8; 32]);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.copy_from_slice(&self.0);
        Ok(())
    }
}

impl CryptoRng for TestRng {}


fn full_flow(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let z_left = [0x55u8; 32];
    let z_right = [0xaau8; 32];

    // d drives rho which is not constant time; ek contains rho sent in the clear
    // See step 1 & 19 of k_pke_key_gen
    let d = [0u8; 32];

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut z_refs = [&z_right; ITERATIONS_OUTER];

    // Interleave left and right
    for i in (0..(ITERATIONS_OUTER)).step_by(2) {
        classes[i] = Class::Left;
        z_refs[i] = &z_left;
    }

    for (class, &z) in classes.into_iter().zip(z_refs.iter()) {
        runner.run_one(class, || {
            let mut rng = TestRng(*z); // regurgitates z as rng in encaps
            for _ in 0..ITERATIONS_INNER {
                let (ek, dk) = ml_kem_512::KG::keygen_from_seed(d, *z);
                let (ssk1, ct) = ek.try_encaps_with_rng(&mut rng).unwrap(); // uses 1 rng
                let ssk2 = dk.try_decaps(&ct).unwrap();
                assert_eq!(ssk1, ssk2);
            }
        })
    }
}

ctbench_main!(full_flow);
