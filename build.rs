use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn main() {
    let so_path = Path::new("/usr/lib64/libpython3.9.so");
    let so_versioned = Path::new("/usr/lib64/libpython3.9.so.1.0");

    if so_path.exists() {
        println!("cargo:rustc-link-search=native=/usr/lib64");
    } else if so_versioned.exists() {
        let out_dir = env::var("OUT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/pylib"));
        let pylib_dir = out_dir.join("pylib");
        let _ = fs::create_dir_all(&pylib_dir);
        let link_path = pylib_dir.join("libpython3.9.so");
        if !link_path.exists() {
            let _ = symlink(so_versioned, &link_path);
        }
        println!("cargo:rustc-link-search=native={}", pylib_dir.display());
    }
}
