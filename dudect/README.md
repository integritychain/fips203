Constant-time measurement of `fips203` key generation, encapsulation and decapsulation with
[dudect-bencher](https://docs.rs/dudect-bencher/latest/dudect_bencher/). Each sample derives an
ML-KEM-512 key pair from seeds, encapsulates to it and decapsulates the result, five times. The seed
`d` is the same in both classes: it drives rho, which is expanded in variable time but sent in the
clear in the encapsulation key. The two classes use different seeds `z` and encapsulation randomness
(every byte 0x55, or every byte 0xAA) and alternate sample by sample, so a timing difference between
them shows up as a large t-value. Results depend on the machine and configuration; they are
evidence, not proof.

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 14, 2026
13th Gen Intel® Core™ i7-13700K × 24  Circa 2022  Rust 1.98.1  fips203 v0.5.0

$ cd dudect  # this directory
$ cargo +stable clean
     Removed 0 files
$ time RUSTFLAGS="-C target-cpu=native" taskset -c 12 cargo +stable run --release  # A ~42 minute run on one P-core

...
    Finished `release` profile [optimized + debuginfo] target(s) in 18.60s
     Running `target/release/fips203-dudect`

running 1 bench
bench full_flow seeded with 0x41cdcaf1bba52d0d
bench full_flow ... : n == +0.561M, max t = +1.49425, max tau = +0.00199, (5/tau)^2 = 6283744

dudect benches complete


real	41m57.672s
user	41m56.036s
sys	0m1.461s
~~~
