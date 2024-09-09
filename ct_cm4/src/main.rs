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
use subtle::{ConditionallySelectable, ConstantTimeEq};


// Test RNG to regurgitate incremented values when 'asked' except rho every i mod 4 == 0 (seed d)
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
        let supply_rho = (self.value & 0x03).ct_eq(&0);
        let target = u32::conditional_select(&self.value, &self.rho, supply_rho);
        out[0..4].copy_from_slice(&target.to_be_bytes());
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

    let mut rng = TestRng { rho: 999, value: 4 }; // arbitrary choice (value must be mult of 4)
    let mut spare_draw = [0u8; 32];
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

        ///////////////////// Start measurement period
        asm::isb();
        let start = DWT::cycle_count();
        asm::isb();

        let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng(&mut rng).unwrap();
        let (ssk1, ct) = ek.try_encaps_with_rng(&mut rng).unwrap();
        let ssk2 = dk.try_decaps(&ct).unwrap();
        assert_eq!(ssk1.into_bytes(), ssk2.into_bytes());

        asm::isb();
        let finish = DWT::cycle_count();
        asm::isb();
        ///////////////////// Finish measurement period

        let _ = rng.try_fill_bytes(&mut spare_draw).unwrap(); // ease our lives; multiple of 4
        let count = finish - start;

        // each rho should have a fixed cycle count
        if (i % 1000) == 0 {
            rng.rho += 1
        };
        // capture the cycle count
        if (i % 1000) == 2 {
            expected_cycles = count
        };
        // make sure it is constant
        if ((i % 1000) > 2) & (count != expected_cycles) {
            panic!("Non constant-time operation!! iteration:{} cycles:{}", i, count)
        };
        if i % 100 == 0 {
            rprintln!("Iteration {} cycle count: {}", i, count)
        };
    }
}
