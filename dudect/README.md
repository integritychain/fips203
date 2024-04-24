An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
April 24, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

bench full_flow ... : n == +0.085M, max t = -0.58644, max tau = -0.00201, (5/tau)^2 = 6176143
bench full_flow ... : n == +0.399M, max t = -1.17381, max tau = -0.00186, (5/tau)^2 = 7237331
bench full_flow ... : n == +0.517M, max t = +1.41846, max tau = +0.00197, (5/tau)^2 = 6418524
bench full_flow ... : n == +0.752M, max t = +1.17197, max tau = +0.00135, (5/tau)^2 = 13689679
bench full_flow ... : n == +0.822M, max t = +1.57820, max tau = +0.00174, (5/tau)^2 = 8248031
bench full_flow ... : n == +0.959M, max t = +1.55916, max tau = +0.00159, (5/tau)^2 = 9865317
bench full_flow ... : n == +1.130M, max t = +1.93067, max tau = +0.00182, (5/tau)^2 = 7577378
bench full_flow ... : n == +1.302M, max t = +2.06522, max tau = +0.00181, (5/tau)^2 = 7633125
bench full_flow ... : n == +1.476M, max t = +1.99294, max tau = +0.00164, (5/tau)^2 = 9292719
bench full_flow ... : n == +1.624M, max t = +2.10232, max tau = +0.00165, (5/tau)^2 = 9186320
bench full_flow ... : n == +1.857M, max t = +2.09333, max tau = +0.00154, (5/tau)^2 = 10592170
bench full_flow ... : n == +1.943M, max t = +2.36765, max tau = +0.00170, (5/tau)^2 = 8664773
bench full_flow ... : n == +2.042M, max t = +2.48002, max tau = +0.00174, (5/tau)^2 = 8300120
...
~~~
