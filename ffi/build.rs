use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libfips203.so.{}",
             std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap());

    // Write minimal pkg-config file:
    let out_dir = env::var("OUT_DIR").unwrap();
    let libname = "fips203";
    let mut desc = std::env::var("CARGO_PKG_DESCRIPTION").unwrap();
    // strip beginning text:
    let begin_text = "C shared library exposing ";
    assert!(desc.starts_with(begin_text));
    desc.replace_range(..begin_text.len(), "");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let url = std::env::var("CARGO_PKG_REPOSITORY").unwrap();
    let pc_dest_path = Path::new(&out_dir).join(format!("{libname}.pc"));

    fs::write(pc_dest_path, format!("Name: {libname}
Description: {desc}
Version: {version}
URL: {url}
Libs: -l{libname}
")).unwrap()
}
