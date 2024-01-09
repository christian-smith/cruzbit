use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() {
    let lib_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("lib");
    let is_cuda = env::var("CARGO_FEATURE_CUDA").is_ok();
    let is_opencl = env::var("CARGO_FEATURE_OPENCL").is_ok();

    if is_cuda && is_opencl {
        eprint!("can only build with either cuda or opencl enabled");
        exit(1);
    } else if is_cuda {
        let _ = cmake::Config::new(Path::new("src/cuda"))
            .define("CMAKE_INSTALL_LIBDIR", &lib_dir)
            .build();
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=cruzbit_cuda");
    } else if is_opencl {
        let _ = cmake::Config::new(Path::new("src/opencl"))
            .define("CMAKE_INSTALL_LIBDIR", &lib_dir)
            .build();
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=cruzbit_ocl");
    }
}
