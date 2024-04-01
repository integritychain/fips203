Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions significantly impact performance.

Performance optimizations will quickly follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition,
then fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 1, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [52.346 µs 52.370 µs 52.386 µs]
ml_kem_768  KeyGen      time:   [90.119 µs 90.518 µs 91.110 µs]
ml_kem_1024 KeyGen      time:   [140.77 µs 140.96 µs 141.13 µs]

ml_kem_512  Encaps      time:   [66.662 µs 66.938 µs 67.355 µs]
ml_kem_768  Encaps      time:   [107.48 µs 107.54 µs 107.62 µs]
ml_kem_1024 Encaps      time:   [156.71 µs 156.93 µs 157.19 µs]

ml_kem_512  Decaps      time:   [94.679 µs 94.720 µs 94.749 µs]
ml_kem_768  Decaps      time:   [150.44 µs 151.12 µs 152.29 µs]
ml_kem_1024 Decaps      time:   [213.44 µs 214.01 µs 214.65 µs]
~~~
