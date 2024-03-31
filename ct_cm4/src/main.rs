#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::entry;
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use microbit::{
    board::Board,
    hal::{pac::DWT, prelude::OutputPin},
};
use panic_rtt_target as _;
use rand_core::{CryptoRng, RngCore};
use rtt_target::{rprintln, rtt_init_print};

// Simplistic RNG to regurgitate incremented values when 'asked'
struct TestRng {
    value: u32,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.iter_mut().for_each(|b| *b = 0);
        out[0..4].copy_from_slice(&self.value.to_be_bytes())
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        self.value = self.value.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for TestRng {}


#[entry]
fn main() -> ! {
    let mut board = Board::take().unwrap();
    board.DCB.enable_trace();
    board.DWT.enable_cycle_counter();
    board.display_pins.col1.set_low().unwrap();
    rtt_init_print!();

    let mut rng = TestRng { value: 1 };
    let mut expected_cycles = 0;
    let mut i = 0u32;

    loop {
        if (i % 100) == 0 {
            board.display_pins.row1.set_high().unwrap();
        };
        if (i % 100) == 50 {
            board.display_pins.row1.set_low().unwrap();
        };
        i += 1;

        asm::isb();
        let start = DWT::cycle_count();
        asm::isb();

        let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let (ssk1, ct) = ek.try_encaps_with_rng_vt(&mut rng).unwrap();
        let ssk2 = dk.try_decaps_vt(&ct).unwrap();
        assert_eq!(ssk1.into_bytes(), ssk2.into_bytes());

        asm::isb();
        let finish = DWT::cycle_count();
        asm::isb();

        let count = finish - start;
        if i == 5 {
            expected_cycles = count
        };
        if (i > 5) & (count != expected_cycles) {
            panic!("Non constant-time operation!! {}", i)
        };
        if i % 10 == 0 {
            rprintln!("Iteration {} cycle count: {}", i, count);
        }
    }
}
