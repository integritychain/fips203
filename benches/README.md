Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 13, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [28.157 µs 28.164 µs 28.172 µs]
ml_kem_768  KeyGen      time:   [47.946 µs 47.963 µs 47.985 µs]
ml_kem_1024 KeyGen      time:   [74.143 µs 74.152 µs 74.162 µs]

ml_kem_512  Encaps      time:   [28.580 µs 28.584 µs 28.588 µs]
ml_kem_768  Encaps      time:   [45.487 µs 45.512 µs 45.542 µs]
ml_kem_1024 Encaps      time:   [67.062 µs 67.144 µs 67.252 µs]

ml_kem_512  Decaps      time:   [40.099 µs 40.111 µs 40.123 µs]
ml_kem_768  Decaps      time:   [61.509 µs 61.532 µs 61.558 µs]
ml_kem_1024 Decaps      time:   [91.470 µs 91.606 µs 91.744 µs]
~~~
