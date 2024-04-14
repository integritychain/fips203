Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 14, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [28.662 µs 28.670 µs 28.676 µs]
ml_kem_768  KeyGen      time:   [48.350 µs 48.358 µs 48.365 µs]
ml_kem_1024 KeyGen      time:   [74.210 µs 74.267 µs 74.330 µs]

ml_kem_512  Encaps      time:   [29.552 µs 29.571 µs 29.594 µs]
ml_kem_768  Encaps      time:   [47.287 µs 47.323 µs 47.381 µs]
ml_kem_1024 Encaps      time:   [70.049 µs 70.126 µs 70.210 µs]

ml_kem_512  Decaps      time:   [40.038 µs 40.085 µs 40.135 µs]
ml_kem_768  Decaps      time:   [62.921 µs 63.354 µs 64.216 µs]
ml_kem_1024 Decaps      time:   [87.703 µs 87.765 µs 87.828 µs]
~~~
