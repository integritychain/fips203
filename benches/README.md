Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 24, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [29.536 µs 29.556 µs 29.585 µs]
ml_kem_768  KeyGen      time:   [49.028 µs 49.070 µs 49.120 µs]
ml_kem_1024 KeyGen      time:   [75.570 µs 75.942 µs 76.418 µs]

ml_kem_512  Encaps      time:   [30.290 µs 30.303 µs 30.321 µs]
ml_kem_768  Encaps      time:   [47.582 µs 47.600 µs 47.627 µs]
ml_kem_1024 Encaps      time:   [69.700 µs 69.741 µs 69.813 µs]

ml_kem_512  Decaps      time:   [40.703 µs 40.819 µs 41.022 µs]
ml_kem_768  Decaps      time:   [63.069 µs 63.108 µs 63.163 µs]
ml_kem_1024 Decaps      time:   [90.232 µs 90.287 µs 90.375 µs]
~~~
