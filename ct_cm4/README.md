An example for the STM Discovery Board -- https://docs.rust-embedded.org/discovery/f3discovery/index.html

One-off setup:

~~~
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools-preview
~~~

You will need to be running with two windows in parallel.

1. In the first window:

   ~~~
   $ cd ct_cm4   # <here>
   $ cargo build --target thumbv7em-none-eabihf
   $ cargo readobj --target thumbv7em-none-eabihf --bin ct_cm4-fips203 -- --file-header  # double-checks built object
   $ cargo size --bin ct_cm4-fips203 --release -- -A
   ~~~

2. In the second window:

   ~~~
   $ cd /tmp && openocd -f interface/stlink-v2-1.cfg -f target/stm32f3x.cfg
   ~~~

3. Back to the first window:

   ~~~
   $ cargo run

   then:
      layout src
      break k_pke.rs:29
      continue
      s
   ~~~
