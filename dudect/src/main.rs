use dudect_bencher::{BenchRng, Class, ctbench_main, CtRunner};
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen};
use rand_core::{CryptoRng, RngCore};

// Could also be ml_kem_768 or ml_kem_1024.
use crate::ml_kem_512::{CipherText, DecapsKey, EncapsKey};


// Dummy RNG that regurgitates zeros when 'asked'
struct MyRng();
impl RngCore for MyRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, out: &mut [u8]) { out.iter_mut().for_each(|b| *b = 0); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for MyRng {}


fn encaps(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 100;
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
            let mut my_rng = MyRng {};
            for _ in 0..ITERATIONS_INNER {
                let _ = input.try_encaps_with_rng_vt(&mut my_rng);
            }
        })
    }
}


fn decaps(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 100;
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
