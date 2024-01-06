#![no_std]
#![no_main]
// TODO: ----->>> THIS IS A WORK IN PROGRESS
////////////////////////////////////////////
#![allow(dead_code)]
#![allow(clippy::write_with_newline)]
// Using STM Discovery Board -- https://docs.rust-embedded.org/discovery/f3discovery/index.html
//
// One-off
//   rustup target add thumbv7em-none-eabihf
//   rustup component add llvm-tools-preview
//
// cd ct_cm4
// cargo build --target thumbv7em-none-eabihf   # --target not needed?
// cargo readobj --target thumbv7em-none-eabihf --bin ct_cm4-fips203 -- --file-header  # double-checks built object
// (In another window) cd /tmp && openocd -f interface/stlink-v2-1.cfg -f target/stm32f3x.cfg
// cargo run
// layout src
// break main.rs:93
// continue
// s


// Embedded heap allocator (since no_std)
extern crate alloc;

// CPU support
use core::fmt::Write;
use core::mem::MaybeUninit;

// for hio
//use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use cortex_m_semihosting::hio;
use rand_core::{CryptoRng, RngCore};
// Board support
use stm32f3_discovery::leds::Leds;
use stm32f3_discovery::stm32f3xx_hal::{pac, prelude::*};
use stm32f3_discovery::switch_hal::OutputSwitch;

use embedded_alloc::Heap;
use fips203::ml_kem_512;
// Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen};


#[global_allocator]
static HEAP: Heap = Heap::empty();

// This function prints to semihosting
fn print_semi(msg: &str, delta: u32) {
    let mut stdout = hio::hstdout()
        .map_err(|_| core::fmt::Error)
        .expect("hio fail");
    write!(stdout, "{} delta is #{}\n", msg, delta).expect("write fail");
}

// Dummy RNG
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


#[entry]
fn main() -> ! {
    // Configure heap
    const HEAP_SIZE: usize = 10 * 1024;
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    // Configure MCU
    let device_periphs = pac::Peripherals::take().expect("device_periphs fail");
    let mut reset_and_clock_control = device_periphs.RCC.constrain();
    //let mut core_periphs = cortex_m::Peripherals::take().expect("core_periphs fail");
    //core_periphs.DWT.enable_cycle_counter();

    // Initialize LEDs
    let mut gpioe = device_periphs.GPIOE.split(&mut reset_and_clock_control.ahb);
    #[rustfmt::skip]
        let mut leds = Leds::new(gpioe.pe8, gpioe.pe9, gpioe.pe10, gpioe.pe11, gpioe.pe12,
                                 gpioe.pe13, gpioe.pe14, gpioe.pe15, &mut gpioe.moder, &mut gpioe.otyper).into_array();

    let mut my_rng = MyRng {};
    let mut i = 0u32;
    loop {
        i = if i % 10 == 0 {
            leds[0].off().ok();
            1
        } else {
            leds[0].on().ok();
            i + 1
        };
        //cortex_m::asm::isb();
        //let start = DWT::cycle_count();
        //cortex_m::asm::isb();

        //let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut my_rng).unwrap();
        let res1 = ml_kem_512::KG::try_keygen_with_rng_vt(&mut my_rng);
        if res1.is_ok() {
            let (ek1, dk1) = res1.unwrap();
            let (ssk1, ct) = ek1.try_encaps_with_rng_vt(&mut my_rng).unwrap();
            let ssk2 = dk1.try_decaps_vt(&ct).unwrap();
            assert_eq!(ssk1, ssk2);
        }
        //cortex_m::asm::isb();
        //let finish = DWT::cycle_count();
        //cortex_m::asm::isb();
        ///////////////////// ...timing finished

        //print_semi("Top", finish - start);
        //leds[0].off().ok();
    }
}
