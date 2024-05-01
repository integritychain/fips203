fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libfips203.so.{}",
             std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap());
}
