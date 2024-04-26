use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen};
use rand_core::{CryptoRng, RngCore};
use subtle::{ConditionallySelectable, ConstantTimeEq};


// Simplistic RNG to regurgitate incremented values when 'asked' except rho every 4th time
#[derive(Clone)]
struct TestRng {
    rho: u32,
    value: u32,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.iter_mut().for_each(|b| *b = 0);
        let supply_rho = (self.value & 0x03u32).ct_eq(&1_u32);
        let target = u32::conditional_select(&self.value, &self.rho, supply_rho);
        out[0..4].copy_from_slice(&target.to_be_bytes());
        self.value = self.value.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for TestRng {}


fn full_flow(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let rng_left = TestRng { rho: 9, value: 111 * 4 };
    let rng_right = TestRng { rho: 9, value: 222 * 4 };

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
            let mut spare_draw = [0u8; 32];
            for _ in 0..ITERATIONS_INNER {
                let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng(&mut rng).unwrap(); // uses 2 rng
                let (ssk1, ct) = ek.try_encaps_with_rng(&mut rng).unwrap(); // uses 1 rng
                let ssk2 = dk.try_decaps(&ct).unwrap();
                assert_eq!(ssk1, ssk2);
                let _ = rng.try_fill_bytes(&mut spare_draw).unwrap(); // ease our lives; multiple of 4
            }
        })
    }
}

ctbench_main!(full_flow);
