#![no_std]
#![no_main]
////////////////////////////////////////////
#![allow(dead_code)]
#![allow(clippy::write_with_newline)]

use cortex_m_rt::entry;
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen};
use rand_core::{CryptoRng, RngCore};
use stm32f3_discovery::leds::Leds;
use stm32f3_discovery::stm32f3xx_hal::{pac, prelude::*};
use stm32f3_discovery::switch_hal::OutputSwitch;

// Dummy RNG that regurgitates zeros when asked
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


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }


#[entry]
fn main() -> ! {

    // Configure MCU
    let device_periphs = pac::Peripherals::take().unwrap();
    let mut reset_and_clock_control = device_periphs.RCC.constrain();

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

        let res1 = ml_kem_512::KG::try_keygen_with_rng_vt(&mut my_rng);
        // if res1.is_ok() {
        //     let (ek1, dk1) = res1.unwrap();
        //     let (ssk1, ct) = ek1.try_encaps_with_rng_vt(&mut my_rng).unwrap();
        //     let ssk2 = dk1.try_decaps_vt(&ct).unwrap();
        //     assert_eq!(ssk1, ssk2);
        // }
        //cortex_m::asm::isb();
        //let finish = DWT::cycle_count();
        //cortex_m::asm::isb();
        ///////////////////// ...timing finished

        //print_semi("Top", finish - start);
        //leds[0].off().ok();
    }
}
