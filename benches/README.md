Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 24, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [28.950 µs 28.988 µs 29.028 µs]
ml_kem_768  KeyGen      time:   [47.988 µs 48.048 µs 48.104 µs]
ml_kem_1024 KeyGen      time:   [75.186 µs 75.242 µs 75.315 µs]

ml_kem_512  Encaps      time:   [29.574 µs 29.589 µs 29.609 µs]
ml_kem_768  Encaps      time:   [46.665 µs 46.752 µs 46.889 µs]
ml_kem_1024 Encaps      time:   [70.703 µs 70.809 µs 70.931 µs]

ml_kem_512  Decaps      time:   [39.643 µs 39.671 µs 39.702 µs]
ml_kem_768  Decaps      time:   [61.060 µs 61.141 µs 61.221 µs]
ml_kem_1024 Decaps      time:   [87.695 µs 87.770 µs 87.856 µs]
~~~
