Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 203.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 26, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [28.597 µs 28.599 µs 28.600 µs]
ml_kem_768  KeyGen      time:   [47.513 µs 47.534 µs 47.553 µs]
ml_kem_1024 KeyGen      time:   [74.790 µs 74.796 µs 74.804 µs]

ml_kem_512  Encaps      time:   [29.674 µs 29.688 µs 29.705 µs]
ml_kem_768  Encaps      time:   [46.599 µs 46.616 µs 46.635 µs]
ml_kem_1024 Encaps      time:   [70.481 µs 70.485 µs 70.491 µs]

ml_kem_512  Decaps      time:   [39.454 µs 39.471 µs 39.495 µs]
ml_kem_768  Decaps      time:   [61.607 µs 62.091 µs 62.701 µs]
ml_kem_1024 Decaps      time:   [86.873 µs 86.894 µs 86.908 µs]
~~~
