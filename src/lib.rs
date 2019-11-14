// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![crate_type = "lib"]

#![cfg_attr(feature = "rustc", feature(rustc_private))]

#![deny(unused_imports)]

#[cfg(feature = "rustc")]
extern crate rustc;

#[cfg(unix)]
extern crate libc;
extern crate test;

#[cfg(feature = "tmp")] extern crate tempfile;

extern crate log;
extern crate regex;
extern crate filetime;
extern crate diff;
extern crate serde;
extern crate serde_json;
extern crate serde_derive;
extern crate rustfix;
extern crate lazy_static;
extern crate walkdir;

use crate::common::{expected_output_path, output_base_dir, output_relative_path, UI_EXTENSIONS};
use crate::common::{TestPaths};
use crate::common::{DebugInfoCdb, DebugInfoGdbLldb, DebugInfoGdb, DebugInfoLldb, Mode, Pretty};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use crate::util::logv;
use walkdir::WalkDir;
use log::*;

use self::header::{EarlyProps, Ignore};

pub mod uidiff;
pub mod util;
mod json;
pub mod header;
pub mod runtest;
pub mod common;
pub mod errors;
mod read2;
mod raise_fd_limit;

pub use crate::common::Config;

pub fn log_config(config: &Config) {
    let c = config;
    logv(c, "configuration:".to_string());
    logv(
        c,
        format!("compile_lib_path: {:?}", config.compile_lib_path),
    );
    logv(c, format!("run_lib_path: {:?}", config.run_lib_path));
    logv(c, format!("rustc_path: {:?}", config.rustc_path.display()));
    logv(c, format!("rustdoc_path: {:?}", config.rustdoc_path));
    logv(c, format!("src_base: {:?}", config.src_base.display()));
    logv(c, format!("build_base: {:?}", config.build_base.display()));
    logv(c, format!("stage_id: {}", config.stage_id));
    logv(c, format!("mode: {}", config.mode));
    logv(c, format!("run_ignored: {}", config.run_ignored));
    logv(
        c,
        format!(
            "filter: {}",
            opt_str(&config.filter.as_ref().map(|re| re.to_owned()))
        ),
    );
    logv(c, format!("filter_exact: {}", config.filter_exact));
    logv(c, format!(
        "force_pass_mode: {}",
        opt_str(&config.force_pass_mode.map(|m| format!("{}", m))),
    ));
    logv(c, format!("runtool: {}", opt_str(&config.runtool)));
    logv(
        c,
        format!("host-rustcflags: {}", opt_str(&config.host_rustcflags)),
    );
    logv(
        c,
        format!("target-rustcflags: {}", opt_str(&config.target_rustcflags)),
    );
    logv(c, format!("target: {}", config.target));
    logv(c, format!("host: {}", config.host));
    logv(
        c,
        format!(
            "android-cross-path: {:?}",
            config.android_cross_path.display()
        ),
    );
    logv(c, format!("adb_path: {:?}", config.adb_path));
    logv(c, format!("adb_test_dir: {:?}", config.adb_test_dir));
    logv(
        c,
        format!("adb_device_status: {}", config.adb_device_status),
    );
    logv(c, format!("ar: {}", config.ar));
    logv(c, format!("linker: {:?}", config.linker));
    logv(c, format!("verbose: {}", config.verbose));
    logv(c, format!("quiet: {}", config.quiet));
    logv(c, "\n".to_string());
}

pub fn opt_str(maybestr: &Option<String>) -> &str {
    match *maybestr {
        None => "(none)",
        Some(ref s) => s,
    }
}

pub fn opt_str2(maybestr: Option<String>) -> String {
    match maybestr {
        None => "(none)".to_owned(),
        Some(s) => s,
    }
}

pub fn run_tests(config: &Config) {
    if config.target.contains("android") {
        if config.mode == DebugInfoGdb || config.mode == DebugInfoGdbLldb {
            println!(
                "{} debug-info test uses tcp 5039 port.\
                 please reserve it",
                config.target
            );

            // android debug-info test uses remote debugger so, we test 1 thread
            // at once as they're all sharing the same TCP port to communicate
            // over.
            //
            // we should figure out how to lift this restriction! (run them all
            // on different ports allocated dynamically).
            env::set_var("RUST_TEST_THREADS", "1");
        }
    }

    match config.mode {
        // Note that we don't need to emit the gdb warning when
        // DebugInfoGdbLldb, so it is ok to list that here.
        DebugInfoGdbLldb | DebugInfoLldb => {
            if let Some(lldb_version) = config.lldb_version.as_ref() {
                if is_blacklisted_lldb_version(&lldb_version[..]) {
                    println!(
                        "WARNING: The used version of LLDB ({}) has a \
                         known issue that breaks debuginfo tests. See \
                         issue #32520 for more information. Skipping all \
                         LLDB-based tests!",
                        lldb_version
                    );
                    return;
                }
            }

            // Some older versions of LLDB seem to have problems with multiple
            // instances running in parallel, so only run one test thread at a
            // time.
            env::set_var("RUST_TEST_THREADS", "1");
        }

        DebugInfoGdb => {
            if config.remote_test_client.is_some() && !config.target.contains("android") {
                println!(
                    "WARNING: debuginfo tests are not available when \
                     testing with remote"
                );
                return;
            }
        }

        DebugInfoCdb | _ => { /* proceed */ }
    }

    // FIXME(#33435) Avoid spurious failures in codegen-units/partitioning tests.
    if let Mode::CodegenUnits = config.mode {
        let _ = fs::remove_dir_all("tmp/partitioning-tests");
    }

    // If we want to collect rustfix coverage information,
    // we first make sure that the coverage file does not exist.
    // It will be created later on.
    if config.rustfix_coverage {
        let mut coverage_file_path = config.build_base.clone();
        coverage_file_path.push("rustfix_missing_coverage.txt");
        if coverage_file_path.exists() {
            if let Err(e) = fs::remove_file(&coverage_file_path) {
                panic!("Could not delete {} due to {}", coverage_file_path.display(), e)
            }
        }
    }

    let opts = test_opts(config);
    let tests = make_tests(config);
    // sadly osx needs some file descriptor limits raised for running tests in
    // parallel (especially when we have lots and lots of child processes).
    // For context, see #8904
    unsafe {
        raise_fd_limit::raise_fd_limit();
    }
    // Prevent issue #21352 UAC blocking .exe containing 'patch' etc. on Windows
    // If #11207 is resolved (adding manifest to .exe) this becomes unnecessary
    env::set_var("__COMPAT_LAYER", "RunAsInvoker");

    // Let tests know which target they're running as
    env::set_var("TARGET", &config.target);

    let res = test::run_tests_console(&opts, tests);
    match res {
        Ok(true) => {}
        Ok(false) => panic!("Some tests failed"),
        Err(e) => {
            println!("I/O failure during tests: {:?}", e);
        }
    }
}

pub fn test_opts(config: &Config) -> test::TestOpts {
    test::TestOpts {
        #[cfg(rustc)]
        exclude_should_panic: false,
        filter: config.filter.clone(),
        filter_exact: config.filter_exact,
        run_ignored: if config.run_ignored {
            test::RunIgnored::Yes
        } else {
            test::RunIgnored::No
        },
        format: if config.quiet {
            test::OutputFormat::Terse
        } else {
            test::OutputFormat::Pretty
        },
        logfile: config.logfile.clone(),
        run_tests: true,
        bench_benchmarks: true,
        nocapture: match env::var("RUST_TEST_NOCAPTURE") {
            Ok(val) => &val != "0",
            Err(_) => false,
        },
        color: config.color,
        test_threads: None,
        skip: vec![],
        list: false,
        options: test::Options::new(),
        #[cfg(rustc)]
        time_options: None,
    }
}

pub fn make_tests(config: &Config) -> Vec<test::TestDescAndFn> {
    debug!("making tests from {:?}", config.src_base.display());
    let mut tests = Vec::new();
    collect_tests_from_dir(
        config,
        &config.src_base,
        &config.src_base,
        &PathBuf::new(),
        &mut tests,
    ).unwrap();
    tests
}

fn collect_tests_from_dir(
    config: &Config,
    base: &Path,
    dir: &Path,
    relative_dir_path: &Path,
    tests: &mut Vec<test::TestDescAndFn>,
) -> io::Result<()> {
    // Ignore directories that contain a file named `compiletest-ignore-dir`.
    if dir.join("compiletest-ignore-dir").exists() {
        return Ok(());
    }

    if config.mode == Mode::RunMake && dir.join("Makefile").exists() {
        let paths = TestPaths {
            file: dir.to_path_buf(),
            relative_dir: relative_dir_path.parent().unwrap().to_path_buf(),
        };
        tests.extend(make_test(config, &paths));
        return Ok(());
    }

    // If we find a test foo/bar.rs, we have to build the
    // output directory `$build/foo` so we can write
    // `$build/foo/bar` into it. We do this *now* in this
    // sequential loop because otherwise, if we do it in the
    // tests themselves, they race for the privilege of
    // creating the directories and sometimes fail randomly.
    let build_dir = output_relative_path(config, relative_dir_path);
    fs::create_dir_all(&build_dir).unwrap();

    // Add each `.rs` file as a test, and recurse further on any
    // subdirectories we find, except for `aux` directories.
    for file in fs::read_dir(dir)? {
        let file = file?;
        let file_path = file.path();
        let file_name = file.file_name();
        if is_test(&file_name) {
            debug!("found test file: {:?}", file_path.display());
            let paths = TestPaths {
                file: file_path,
                relative_dir: relative_dir_path.to_path_buf(),
            };
            tests.extend(make_test(config, &paths))
        } else if file_path.is_dir() {
            let relative_file_path = relative_dir_path.join(file.file_name());
            if &file_name != "auxiliary" {
                debug!("found directory: {:?}", file_path.display());
                collect_tests_from_dir(config, base, &file_path, &relative_file_path, tests)?;
            }
        } else {
            debug!("found other file/directory: {:?}", file_path.display());
        }
    }
    Ok(())
}


/// Returns true if `file_name` looks like a proper test file name.
pub fn is_test(file_name: &OsString) -> bool {
    let file_name = file_name.to_str().unwrap();

    if !file_name.ends_with(".rs") {
        return false;
    }

    // `.`, `#`, and `~` are common temp-file prefixes.
    let invalid_prefixes = &[".", "#", "~"];
    !invalid_prefixes.iter().any(|p| file_name.starts_with(p))
}

pub fn make_test(config: &Config, testpaths: &TestPaths) -> Vec<test::TestDescAndFn> {
    let early_props = if config.mode == Mode::RunMake {
        // Allow `ignore` directives to be in the Makefile.
        EarlyProps::from_file(config, &testpaths.file.join("Makefile"))
    } else {
        EarlyProps::from_file(config, &testpaths.file)
    };

    // The `should-fail` annotation doesn't apply to pretty tests,
    // since we run the pretty printer across all tests by default.
    // If desired, we could add a `should-fail-pretty` annotation.
    let should_panic = match config.mode {
        Pretty => test::ShouldPanic::No,
        _ => if early_props.should_fail {
            test::ShouldPanic::Yes
        } else {
            test::ShouldPanic::No
        },
    };

    // Incremental tests are special, they inherently cannot be run in parallel.
    // `runtest::run` will be responsible for iterating over revisions.
    let revisions = if early_props.revisions.is_empty() || config.mode == Mode::Incremental {
        vec![None]
    } else {
        early_props.revisions.iter().map(|r| Some(r)).collect()
    };
    revisions
        .into_iter()
        .map(|revision| {
            // Debugging emscripten code doesn't make sense today
            let ignore = early_props.ignore == Ignore::Ignore
                || !up_to_date(
                    config,
                    testpaths,
                    &early_props,
                    revision.map(|s| s.as_str()),
                )
                || ((config.mode == DebugInfoGdbLldb || config.mode == DebugInfoCdb ||
                     config.mode == DebugInfoGdb || config.mode == DebugInfoLldb)
                    && config.target.contains("emscripten"))
                || (config.mode == DebugInfoGdb && !early_props.ignore.can_run_gdb())
                || (config.mode == DebugInfoLldb && !early_props.ignore.can_run_lldb());
            test::TestDescAndFn {
                desc: test::TestDesc {
                    name: make_test_name(config, testpaths, revision),
                    ignore,
                    should_panic,
                    allow_fail: false,
                },
                testfn: make_test_closure(config, early_props.ignore, testpaths, revision),
            }
        })
        .collect()
}

fn stamp(config: &Config, testpaths: &TestPaths, revision: Option<&str>) -> PathBuf {
    output_base_dir(config, testpaths, revision).join("stamp")
}

fn up_to_date(
    config: &Config,
    testpaths: &TestPaths,
    props: &EarlyProps,
    revision: Option<&str>,
) -> bool {
    let stamp_name = stamp(config, testpaths, revision);
    // Check hash.
    let contents = match fs::read_to_string(&stamp_name) {
        Ok(f) => f,
        Err(ref e) if e.kind() == ErrorKind::InvalidData => panic!("Can't read stamp contents"),
        Err(_) => return true,
    };
    let expected_hash = runtest::compute_stamp_hash(config);
    if contents != expected_hash {
        return true;
    }

    // Check timestamps.
    let rust_src_dir = config
        .find_rust_src_root()
        .expect("Could not find Rust source root");
    let stamp = Stamp::from_path(&stamp_name);
    let mut inputs = vec![Stamp::from_path(&testpaths.file), Stamp::from_path(&config.rustc_path)];
    inputs.extend(
        props
            .aux
            .iter()
            .map(|aux| {
                Stamp::from_path(&testpaths.file.parent().unwrap().join("auxiliary").join(aux))
            }),
    );
    // Relevant pretty printer files
    let pretty_printer_files = [
        "src/etc/debugger_pretty_printers_common.py",
        "src/etc/gdb_load_rust_pretty_printers.py",
        "src/etc/gdb_rust_pretty_printing.py",
        "src/etc/lldb_batchmode.py",
        "src/etc/lldb_rust_formatters.py",
    ];
    inputs.extend(pretty_printer_files.iter().map(|pretty_printer_file| {
        Stamp::from_path(&rust_src_dir.join(pretty_printer_file))
    }));
    inputs.extend(Stamp::from_dir(&config.run_lib_path));
    if let Some(ref rustdoc_path) = config.rustdoc_path {
        inputs.push(Stamp::from_path(&rustdoc_path));
        inputs.push(Stamp::from_path(&rust_src_dir.join("src/etc/htmldocck.py")));
    }

    // UI test files.
    inputs.extend(UI_EXTENSIONS.iter().map(|extension| {
        let path = &expected_output_path(testpaths, revision, &config.compare_mode, extension);
        Stamp::from_path(path)
    }));

    // Compiletest itself.
    inputs.extend(Stamp::from_dir(&rust_src_dir.join("src/tools/compiletest/")));

    inputs.iter().any(|input| input > &stamp)
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq)]
struct Stamp {
    time: SystemTime,
    file: PathBuf,
}

impl Stamp {
    fn from_path(p: &Path) -> Self {
        let time = fs::metadata(p)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        Stamp {
            time,
            file: p.into(),
        }
    }

    fn from_dir(path: &Path) -> impl Iterator<Item = Stamp> {
        WalkDir::new(path)
            .into_iter()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                let time = (|| -> io::Result<_> { entry.metadata()?.modified() })();

                Stamp {
                    time: time.unwrap_or(SystemTime::UNIX_EPOCH),
                    file: entry.path().into(),
                }
            })
    }
}

fn make_test_name(
    config: &Config,
    testpaths: &TestPaths,
    revision: Option<&String>,
) -> test::TestName {
    // Convert a complete path to something like
    //
    //    ui/foo/bar/baz.rs
    let path = PathBuf::from(config.src_base.file_name().unwrap())
        .join(&testpaths.relative_dir)
        .join(&testpaths.file.file_name().unwrap());
    let mode_suffix = match config.compare_mode {
        Some(ref mode) => format!(" ({})", mode.to_str()),
        None => String::new(),
    };
    test::DynTestName(format!(
        "[{}{}] {}{}",
        config.mode,
        mode_suffix,
        path.display(),
        revision.map_or("".to_string(), |rev| format!("#{}", rev))
    ))
}

fn make_test_closure(
    config: &Config,
    ignore: Ignore,
    testpaths: &TestPaths,
    revision: Option<&String>,
) -> test::TestFn {
    let mut config = config.clone();
    if config.mode == DebugInfoGdbLldb {
        // If both gdb and lldb were ignored, then the test as a whole
        // would be ignored.
        if !ignore.can_run_gdb() {
            config.mode = DebugInfoLldb;
        } else if !ignore.can_run_lldb() {
            config.mode = DebugInfoGdb;
        }
    }

    let testpaths = testpaths.clone();
    let revision = revision.cloned();
    test::DynTestFn(Box::new(move || {
        let config = config.clone();
        runtest::run(config, &testpaths, revision.as_ref().map(|s| s.as_str()))
    }))
}

/// Returns `true` if the given target is an Android target for the
/// purposes of GDB testing.
fn is_android_gdb_target(target: &String) -> bool {
    match &target[..] {
        "arm-linux-androideabi" | "armv7-linux-androideabi" | "aarch64-linux-android" => true,
        _ => false,
    }
}

fn extract_gdb_version(full_version_line: &str) -> Option<u32> {
    let full_version_line = full_version_line.trim();

    // GDB versions look like this: "major.minor.patch?.yyyymmdd?", with both
    // of the ? sections being optional

    // We will parse up to 3 digits for minor and patch, ignoring the date
    // We limit major to 1 digit, otherwise, on openSUSE, we parse the openSUSE version

    // don't start parsing in the middle of a number
    let mut prev_was_digit = false;
    for (pos, c) in full_version_line.char_indices() {
        if prev_was_digit || !c.is_digit(10) {
            prev_was_digit = c.is_digit(10);
            continue;
        }

        prev_was_digit = true;

        let line = &full_version_line[pos..];

        let next_split = match line.find(|c: char| !c.is_digit(10)) {
            Some(idx) => idx,
            None => continue, // no minor version
        };

        if line.as_bytes()[next_split] != b'.' {
            continue; // no minor version
        }

        let major = &line[..next_split];
        let line = &line[next_split + 1..];

        let (minor, patch) = match line.find(|c: char| !c.is_digit(10)) {
            Some(idx) => if line.as_bytes()[idx] == b'.' {
                let patch = &line[idx + 1..];

                let patch_len = patch
                    .find(|c: char| !c.is_digit(10))
                    .unwrap_or_else(|| patch.len());
                let patch = &patch[..patch_len];
                let patch = if patch_len > 3 || patch_len == 0 {
                    None
                } else {
                    Some(patch)
                };

                (&line[..idx], patch)
            } else {
                (&line[..idx], None)
            },
            None => (line, None),
        };

        if major.len() != 1 || minor.is_empty() {
            continue;
        }

        let major: u32 = major.parse().unwrap();
        let minor: u32 = minor.parse().unwrap();
        let patch: u32 = patch.unwrap_or("0").parse().unwrap();

        return Some(((major * 1000) + minor) * 1000 + patch);
    }

    None
}

fn is_blacklisted_lldb_version(version: &str) -> bool {
    version == "350"
}
