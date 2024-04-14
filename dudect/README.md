An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
April 14, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

bench full_flow ... : n == +0.182M, max t = +1.29070, max tau = +0.00302, (5/tau)^2 = 2735523
bench full_flow ... : n == +0.323M, max t = -1.38512, max tau = -0.00244, (5/tau)^2 = 4206368
bench full_flow ... : n == +0.488M, max t = -1.58404, max tau = -0.00227, (5/tau)^2 = 4865946
bench full_flow ... : n == +0.694M, max t = -1.64031, max tau = -0.00197, (5/tau)^2 = 6444702
bench full_flow ... : n == +0.860M, max t = -1.71572, max tau = -0.00185, (5/tau)^2 = 7307035
bench full_flow ... : n == +1.035M, max t = -1.66358, max tau = -0.00164, (5/tau)^2 = 9346102
bench full_flow ... : n == +1.206M, max t = -2.07949, max tau = -0.00189, (5/tau)^2 = 6970472
bench full_flow ... : n == +1.375M, max t = -2.29981, max tau = -0.00196, (5/tau)^2 = 6499633
bench full_flow ... : n == +1.548M, max t = -2.34428, max tau = -0.00188, (5/tau)^2 = 7041088
bench full_flow ... : n == +1.721M, max t = -2.43307, max tau = -0.00185, (5/tau)^2 = 7267865
bench full_flow ... : n == +1.892M, max t = -2.54895, max tau = -0.00185, (5/tau)^2 = 7281281
bench full_flow ... : n == +2.063M, max t = -2.67748, max tau = -0.00186, (5/tau)^2 = 7194446
...
~~~
