#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::entry;
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use microbit::{board::Board, hal::{pac::DWT, prelude::OutputPin}};
use rand_chacha::rand_core::SeedableRng;
use rtt_target::{rprintln, rtt_init_print};

use panic_rtt_target as _;


#[entry]
fn main() -> ! {
    let mut board = Board::take().unwrap();
    board.DCB.enable_trace();
    board.DWT.enable_cycle_counter();
    board.display_pins.col1.set_low().unwrap();
    rtt_init_print!();

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    let mut expected_cycles = 0;
    let mut i = 0u32;

    loop {
        if (i % 100) == 0 { board.display_pins.row1.set_high().unwrap(); };
        if (i % 100) == 50 { board.display_pins.row1.set_low().unwrap(); };
        i += 1;

        rng.set_word_pos(1024 * i as u128);  // Removes odd variability in drawing rng data

        asm::isb();
        let start = DWT::cycle_count();
        asm::isb();

        let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let (ssk1, ct) = ek.try_encaps_with_rng_vt(&mut rng).unwrap();
        let ssk2 = dk.try_decaps_vt(&ct).unwrap();

        asm::isb();
        let finish = DWT::cycle_count();
        asm::isb();

        assert_eq!(ssk1.into_bytes(), ssk2.into_bytes());

        let count = finish - start;
        if (i == 5) & (expected_cycles == 0) { expected_cycles = count };
        if (i > 5) & (count != expected_cycles) { panic!("Non constant-time operation!!") };
        if i % 10 == 0 { rprintln!("Iteration {} cycle count: {}", i, count); }
    }
}
