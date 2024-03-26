use dudect_bencher::{BenchRng, Class, ctbench_main, CtRunner};
use fips203::ml_kem_512;
// Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen};
//use fips203::traits::KeyGen;
//use rand_chacha::rand_core::SeedableRng;
use rand_core::{CryptoRng, RngCore};

// Dummy RNG that regurgitates zeros when 'asked'
#[derive(Copy, Clone)]
struct MyRng {
    value: u8,
}
impl RngCore for MyRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, out: &mut [u8]) { out.iter_mut().for_each(|b| *b = self.value); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for MyRng {}

fn full_flow(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let rng_left = MyRng { value: 111 }; //rand_chacha::ChaCha8Rng::seed_from_u64(123);
    let rng_right = MyRng { value: 222 }; //rand_chacha::ChaCha8Rng::seed_from_u64(456);

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut rng_refs = [&rng_right; ITERATIONS_OUTER];

    // Interleave left and right
    for i in (0..(ITERATIONS_OUTER)).step_by(2) {
        classes[i] = Class::Left;
        rng_refs[i] = &rng_left;
    }

    for (class, rng_r) in classes.into_iter().zip(rng_refs.iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let mut rng = **rng_r;  //(*rng_r).clone();
                let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
                let (ssk1, ct) = ek.try_encaps_with_rng_vt(&mut rng).unwrap();
                let ssk2 = dk.try_decaps_vt(&ct).unwrap();
                assert_eq!(ssk1, ssk2);
            }
        })
    }
}

ctbench_main!(full_flow);
