An example for the Microbit v2 Board -- <https://docs.rust-embedded.org/discovery/microbit/index.html>

This example demonstrates the full loop of keygen, encaps, decaps and then shared 
secret equivalency. Cycle counts are measured, displayed, and operation confirmed 
to be constant-time (outside of rho). See the link above for tooling setup.

Requires Rust 1.85 or newer. fixed is pinned to 1.30.0 because 1.31 and later need rustc 1.93 via microbit-v2.

 ~~~
 $ cd ct_cm4   # <here>
 $ cargo embed
 ~~~
