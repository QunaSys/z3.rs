use std::env;

const Z3_HEADER_VAR: &str = "Z3_SYS_Z3_HEADER";

fn main() {
    #[cfg(feature = "static-link-z3")]
    build_z3();

    #[cfg(all(not(feature = "static-link-z3"), feature = "download-z3"))]
    let include_dir = download_z3();

    println!("cargo:rerun-if-changed=build.rs");

    let header = if cfg!(feature = "static-link-z3") {
        "z3/src/api/z3.h".to_string()
    } else if let Ok(header_path) = std::env::var(Z3_HEADER_VAR) {
        header_path
    } else {
        "wrapper.h".to_string()
    };
    println!("cargo:rerun-if-env-changed={}", Z3_HEADER_VAR);
    println!("cargo:rerun-if-changed={}", header);
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    for x in &[
        "ast_kind",
        "ast_print_mode",
        "decl_kind",
        "error_code",
        "goal_prec",
        "param_kind",
        "parameter_kind",
        "sort_kind",
        "symbol_kind",
    ] {
        let mut enum_bindings = bindgen::Builder::default()
            .header(&header)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate_comments(false)
            .rustified_enum(format!("Z3_{}", x))
            .allowlist_type(format!("Z3_{}", x));

        #[cfg(all(not(feature = "static-link-z3"), feature = "download-z3"))]
        {
            enum_bindings = enum_bindings.clang_arg(&format!("-I{}", &include_dir));
        }

        if env::var("TARGET").unwrap() == "wasm32-unknown-emscripten" {
            enum_bindings = enum_bindings.clang_arg(format!(
                "--sysroot={}/upstream/emscripten/cache/sysroot",
                env::var("EMSDK").expect("$EMSDK env var missing. Is emscripten installed?")
            ));
        }
        enum_bindings
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(out_path.join(format!("{}.rs", x)))
            .expect("Couldn't write bindings!");
    }
}

#[cfg(feature = "static-link-z3")]
fn build_z3() {
    let mut cfg = cmake::Config::new("z3");
    cfg
        // Don't build `libz3.so`, build `libz3.a` instead.
        .define("Z3_BUILD_LIBZ3_SHARED", "false")
        // Don't build the Z3 repl.
        .define("Z3_BUILD_EXECUTABLE", "false")
        // Don't build the tests.
        .define("Z3_BUILD_TEST_EXECUTABLES", "false");

    if cfg!(target_os = "windows") {
        // The compiler option -MP and the msbuild option -m
        // can sometimes make builds slower but is measurably
        // faster building Z3 with many cores.
        cfg.cxxflag("-MP");
        cfg.build_arg("-m");
        cfg.cxxflag("-DWIN32");
        cfg.cxxflag("-D_WINDOWS");
    }

    let dst = cfg.build();

    // Z3 needs a C++ standard library. Customize which one we use with the
    // `CXXSTDLIB` environment variable, if needed.
    let cxx = match std::env::var("CXXSTDLIB") {
        Ok(s) if s.is_empty() => None,
        Ok(s) => Some(s),
        Err(_) => {
            let target = std::env::var("TARGET").unwrap();
            if target.contains("msvc") {
                None
            } else if target.contains("apple")
                | target.contains("freebsd")
                | target.contains("openbsd")
            {
                Some("c++".to_string())
            } else {
                Some("stdc++".to_string())
            }
        }
    };

    let mut found_lib_dir = false;
    for lib_dir in &[
        "lib",
        // Fedora builds seem to use `lib64` rather than `lib` for 64-bit
        // builds.
        "lib64",
    ] {
        let full_lib_dir = dst.join(lib_dir);
        if full_lib_dir.exists() {
            if *lib_dir == "lib64" {
                assert_eq!(
                    std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap(),
                    "64"
                );
            }
            println!("cargo:rustc-link-search=native={}", full_lib_dir.display());
            found_lib_dir = true;
            break;
        }
    }
    assert!(
        found_lib_dir,
        "Should have found the lib directory for our built Z3"
    );

    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=static=libz3");
    } else {
        println!("cargo:rustc-link-lib=static=z3");
    }

    if let Some(cxx) = cxx {
        println!("cargo:rustc-link-lib={}", cxx);
    }
}

#[cfg(feature = "download-z3")]
fn download_z3() -> String {
    use reqwest::blocking;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{Cursor, Read, Write};
    use std::path::{Path, PathBuf};
    use zip::ZipArchive;
    fn download(url: &str, sha256: &str) -> Result<Vec<u8>, String> {
        let buf = (|| -> reqwest::Result<_> {
            let response = blocking::get(url)?.error_for_status()?;
            Ok(response.bytes()?.iter().cloned().collect::<Vec<_>>())
        })()
        .map_err(|e| e.to_string())?;
        if sha256 != "PASS" {
            let hash = Sha256::digest(&buf);
            if &format!("{:x}", hash) != sha256 {
                return Err("Hash check failed".to_string());
            }
        }
        Ok(buf)
    }

    fn get_archive_url() -> Option<(String, String)> {
        if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
            Some((
                "https://github.com/Z3Prover/z3/releases/download/z3-4.12.1/z3_solver-4.12.1.0-py2.py3-none-manylinux1_x86_64.whl".into(),
                "41cb9ac460af30b193811eebf919d61cf51a8856bbd74b200cbe6b21e3e955e4".into(),
            ))
        } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
            Some((
                "https://github.com/Z3Prover/z3/releases/download/z3-4.12.1/z3_solver-4.12.1.0-py2.py3-none-macosx_10_16_x86_64.whl".into(),
                "c4f1a53bce12b45698e8e49bd980cd3d3f0298c1ba4cf8c40525af86797565c8".into(),
            ))
        } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            Some((
                "https://github.com/Z3Prover/z3/releases/download/z3-4.12.1/z3_solver-4.12.1.0-py2.py3-none-macosx_11_0_arm64.whl".into(),
                "553ec3cd0188420bc5f007dd873fb0d87075d1b93808eca8c02324eb3a5f6f68".into(),
            ))
        } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
            Some((
                "https://github.com/Z3Prover/z3/releases/download/z3-4.12.1/z3_solver-4.12.1.0-py2.py3-none-win_amd64.whl".into(),
                "aa0e06d42070774a2f89818c412514d41fc84578f32d617de618b214e5ed8154".into(),
            ))
        } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86") {
            Some((
                "https://github.com/Z3Prover/z3/releases/download/z3-4.12.1/z3_solver-4.12.1.0-py2.py3-none-win32.whl".into(),
                "85ff9f59b0f87df4dc0cd52baebb247b8049f2df6aad623151f4c4a21d3d01ac".into(),
            ))
        } else {
            None
        }
    }

    fn write_lib_to_dir(out_dir: &Path) {
        if let Some((url, hash)) = get_archive_url() {
            let archive = download(&url, &hash).unwrap();
            let mut archive = ZipArchive::new(Cursor::new(archive)).unwrap();
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).unwrap();
                let name = file.name().to_string();
                match name.rsplit_once('/') {
                    Some((rpath, basename)) => match rpath.rsplit_once('/') {
                        Some((rrpath, kind))
                            if rrpath == "z3" && (kind == "lib" || kind == "include") =>
                        {
                            let mut buf = Vec::with_capacity(file.size() as usize);
                            file.read_to_end(&mut buf).unwrap();
                            let mut outpath = out_dir.to_path_buf();
                            outpath.push(kind);
                            std::fs::create_dir_all(&outpath).unwrap();
                            outpath.push(basename);
                            let mut outfile = File::create(&outpath).unwrap();
                            outfile.write_all(&buf).unwrap();
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            println!("cargo:Z3_DOWNLOADED=true");
        }
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut out_dir_lib = out_dir.clone();
    out_dir_lib.push("lib");
    let mut out_dir_include = out_dir.clone();
    out_dir_include.push("include");
    if std::fs::read_dir(&out_dir_lib).is_err() || std::fs::read_dir(&out_dir_include).is_err() {
        write_lib_to_dir(&out_dir);
    }
    println!(
        "cargo:rustc-link-search=native={}",
        out_dir_lib.to_str().unwrap()
    );

    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=libz3");
    } else {
        println!("cargo:rustc-link-lib=dylib=z3");
    }

    std::fs::canonicalize(out_dir_include)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}
