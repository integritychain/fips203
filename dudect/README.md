An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

~~~
April 13, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

bench full_flow seeded with 0xea4abed34ed3db26
bench full_flow ... : n == +0.026M, max t = +1.01335, max tau = +0.00630, (5/tau)^2 = 629412
bench full_flow ... : n == +0.337M, max t = -1.75137, max tau = -0.00302, (5/tau)^2 = 2747082
bench full_flow ... : n == +0.497M, max t = -1.51764, max tau = -0.00215, (5/tau)^2 = 5396932
bench full_flow ... : n == +0.740M, max t = -1.61671, max tau = -0.00188, (5/tau)^2 = 7074543
bench full_flow ... : n == +0.786M, max t = -1.32078, max tau = -0.00149, (5/tau)^2 = 11271287
bench full_flow ... : n == +1.064M, max t = -1.33199, max tau = -0.00129, (5/tau)^2 = 14999502
bench full_flow ... : n == +1.193M, max t = -1.67507, max tau = -0.00153, (5/tau)^2 = 10632445
bench full_flow ... : n == +1.383M, max t = -1.77745, max tau = -0.00151, (5/tau)^2 = 10940561
bench full_flow ... : n == +1.437M, max t = -1.46110, max tau = -0.00122, (5/tau)^2 = 16823530
bench full_flow ... : n == +1.746M, max t = -1.52752, max tau = -0.00116, (5/tau)^2 = 18704795
bench full_flow ... : n == +1.937M, max t = -1.54864, max tau = -0.00111, (5/tau)^2 = 20194492
bench full_flow ... : n == +2.125M, max t = -1.50879, max tau = -0.00104, (5/tau)^2 = 23332048
...
~~~
