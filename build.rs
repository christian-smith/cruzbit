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
        println!("cargo:rustc-link-lib=static=cruzbit_cuda");
        link_cuda_runtime();
        link_cpp_runtime();
    } else if is_opencl {
        let _ = cmake::Config::new(Path::new("src/opencl"))
            .define("CMAKE_INSTALL_LIBDIR", &lib_dir)
            .build();
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=cruzbit_ocl");
        link_opencl_runtime();
        link_cpp_runtime();
    }
}

fn link_opencl_runtime() {
    match target_os().as_deref() {
        Some("macos") => println!("cargo:rustc-link-lib=framework=OpenCL"),
        _ => {
            add_vcpkg_link_search();
            println!("cargo:rustc-link-lib=OpenCL");
        }
    }
}

fn link_cuda_runtime() {
    if let Some(cuda_root) = cuda_root() {
        let lib_dir = match target_os().as_deref() {
            Some("windows") => cuda_root.join("lib").join("x64"),
            _ => cuda_root.join("lib64"),
        };
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }

    println!("cargo:rustc-link-lib=cudart");
}

fn link_cpp_runtime() {
    match target_env().as_deref() {
        Some("msvc") => println!("cargo:rustc-link-lib=msvcprt"),
        _ => match target_os().as_deref() {
            Some("macos") => println!("cargo:rustc-link-lib=c++"),
            Some("linux") => println!("cargo:rustc-link-lib=stdc++"),
            _ => {}
        },
    }
}

fn add_vcpkg_link_search() {
    if target_env().as_deref() != Some("msvc") {
        return;
    }

    let Ok(root) = env::var("VCPKG_INSTALLATION_ROOT") else {
        return;
    };

    let triplet = match env::var("TARGET").as_deref() {
        Ok("x86_64-pc-windows-msvc") => "x64-windows",
        Ok("aarch64-pc-windows-msvc") => "arm64-windows",
        _ => return,
    };

    let lib_dir = PathBuf::from(root)
        .join("installed")
        .join(triplet)
        .join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rerun-if-env-changed=VCPKG_INSTALLATION_ROOT");
    println!("cargo:rerun-if-env-changed=TARGET");
}

fn cuda_root() -> Option<PathBuf> {
    env::var_os("CUDA_PATH")
        .or_else(|| env::var_os("CUDA_HOME"))
        .or_else(|| env::var_os("CUDA_ROOT"))
        .map(PathBuf::from)
}

fn target_os() -> Option<String> {
    env::var("CARGO_CFG_TARGET_OS").ok()
}

fn target_env() -> Option<String> {
    env::var("CARGO_CFG_TARGET_ENV").ok()
}
