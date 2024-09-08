An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
September 7, 2024 (FIPS 203 'final')
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017 w/ Rust 1.81

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

running 1 benchmark continuously
bench full_flow seeded with 0x8a47592fedcd9a38
bench full_flow ... : n == +0.199M, max t = +1.85280, max tau = +0.00416, (5/tau)^2 = 1447880
bench full_flow ... : n == +0.398M, max t = +2.04584, max tau = +0.00324, (5/tau)^2 = 2378877
bench full_flow ... : n == +0.521M, max t = -2.17502, max tau = -0.00301, (5/tau)^2 = 2754187
bench full_flow ... : n == +0.695M, max t = -2.16804, max tau = -0.00260, (5/tau)^2 = 3695579
bench full_flow ... : n == +0.995M, max t = +3.73950, max tau = +0.00375, (5/tau)^2 = 1778634
bench full_flow ... : n == +1.194M, max t = +3.57569, max tau = +0.00327, (5/tau)^2 = 2334334
bench full_flow ... : n == +1.394M, max t = +3.60360, max tau = +0.00305, (5/tau)^2 = 2683193
bench full_flow ... : n == +1.594M, max t = +3.44149, max tau = +0.00273, (5/tau)^2 = 3363832
bench full_flow ... : n == +1.794M, max t = +3.30674, max tau = +0.00247, (5/tau)^2 = 4100656
bench full_flow ... : n == +1.994M, max t = +3.13478, max tau = +0.00222, (5/tau)^2 = 5071616
bench full_flow ... : n == +2.193M, max t = +3.01480, max tau = +0.00204, (5/tau)^2 = 6033237
...
~~~
