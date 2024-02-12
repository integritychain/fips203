Figure-of-merit only; no particular care take (wrt turboboost etc).

~~~
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_kem_512  KeyGen      time:   [36.230 µs 36.255 µs 36.283 µs]
ml_kem_768  KeyGen      time:   [60.202 µs 60.259 µs 60.336 µs]
ml_kem_1024 KeyGen      time:   [91.026 µs 91.043 µs 91.061 µs]

ml_kem_512  Encaps      time:   [38.474 µs 38.512 µs 38.562 µs]
ml_kem_768  Encaps      time:   [60.837 µs 60.867 µs 60.914 µs]
ml_kem_1024 Encaps      time:   [90.528 µs 90.561 µs 90.611 µs]

ml_kem_512  Decaps      time:   [49.525 µs 49.562 µs 49.616 µs]
ml_kem_768  Decaps      time:   [78.445 µs 78.513 µs 78.618 µs]
ml_kem_1024 Decaps      time:   [112.85 µs 112.87 µs 112.90 µs]
~~~