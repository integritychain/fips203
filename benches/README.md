Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow ...

~~~
September 7, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017 w/ Rust 1.81

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [27.638 µs 27.651 µs 27.669 µs]
ml_kem_768  KeyGen      time:   [46.425 µs 46.449 µs 46.475 µs]
ml_kem_1024 KeyGen      time:   [69.042 µs 69.141 µs 69.261 µs]

ml_kem_512  Encaps      time:   [27.875 µs 27.883 µs 27.892 µs]
ml_kem_768  Encaps      time:   [44.211 µs 44.217 µs 44.224 µs]
ml_kem_1024 Encaps      time:   [67.138 µs 67.158 µs 67.175 µs]

ml_kem_512  Decaps      time:   [38.597 µs 38.609 µs 38.622 µs]
ml_kem_768  Decaps      time:   [58.355 µs 58.364 µs 58.373 µs]
ml_kem_1024 Decaps      time:   [88.300 µs 88.331 µs 88.369 µs]
~~~
