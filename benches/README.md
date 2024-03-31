Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions impact performance.

Note that performance optimizations will quickly follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular mul & add then reduction.
Also, 'u16' arithmetic has a performance penalty.

~~~
March 31, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [54.335 µs 54.358 µs 54.390 µs]
ml_kem_768  KeyGen      time:   [92.541 µs 92.608 µs 92.689 µs]
ml_kem_1024 KeyGen      time:   [143.35 µs 143.37 µs 143.39 µs]

ml_kem_512  Encaps      time:   [68.294 µs 68.306 µs 68.319 µs]
ml_kem_768  Encaps      time:   [109.51 µs 109.68 µs 109.95 µs]
ml_kem_1024 Encaps      time:   [162.11 µs 162.18 µs 162.25 µs]

ml_kem_512  Decaps      time:   [97.659 µs 97.826 µs 98.043 µs]
ml_kem_768  Decaps      time:   [152.66 µs 152.70 µs 152.74 µs]
ml_kem_1024 Decaps      time:   [219.13 µs 220.42 µs 222.12 µs]
~~~
