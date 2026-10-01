Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

~~~
October 1, 2026
13th Gen Intel® Core™ i7-13700K, Rust 1.85.1
Bench profile: opt-level 3, LTO, codegen-units 1, overflow checks off.
Turbo Boost was left enabled.

$ RUSTFLAGS="-C target-cpu=native" cargo bench --bench benchmark

ml_kem_512  KeyGen      time:   [16.844 µs 16.856 µs 16.870 µs]
ml_kem_768  KeyGen      time:   [28.843 µs 28.885 µs 28.923 µs]
ml_kem_1024 KeyGen      time:   [44.181 µs 44.227 µs 44.276 µs]

ml_kem_512  Encaps      time:   [16.880 µs 16.893 µs 16.908 µs]
ml_kem_768  Encaps      time:   [27.012 µs 27.036 µs 27.063 µs]
ml_kem_1024 Encaps      time:   [39.831 µs 39.854 µs 39.885 µs]

ml_kem_512  Decaps      time:   [23.031 µs 23.048 µs 23.066 µs]
ml_kem_768  Decaps      time:   [35.676 µs 35.727 µs 35.778 µs]
ml_kem_1024 Decaps      time:   [50.837 µs 50.858 µs 50.881 µs]
~~~
