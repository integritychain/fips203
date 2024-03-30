Figure-of-merit only; no particular care hsa been taken to disable turbo-boost etc.
Note that constant-time restrictions impact performance.

Note that performance optimizations will quickly follow the next update to FIPS 203.

~~~
March 22, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [25.924 µs 25.961 µs 26.038 µs]
ml_kem_768  KeyGen      time:   [43.853 µs 43.867 µs 43.883 µs]
ml_kem_1024 KeyGen      time:   [65.706 µs 65.719 µs 65.733 µs]

ml_kem_512  Encaps      time:   [31.405 µs 31.411 µs 31.417 µs]
ml_kem_768  Encaps      time:   [51.315 µs 51.367 µs 51.439 µs]
ml_kem_1024 Encaps      time:   [73.946 µs 73.984 µs 74.038 µs]

ml_kem_512  Decaps      time:   [39.446 µs 39.504 µs 39.560 µs]
ml_kem_768  Decaps      time:   [62.343 µs 62.441 µs 62.574 µs]
ml_kem_1024 Decaps      time:   [89.069 µs 89.134 µs 89.226 µs]
~~~