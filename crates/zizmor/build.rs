use std::fs::{self, File};
use std::path::Path;
use std::{env, io};

use fst::MapBuilder;

fn do_context_capabilities() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = Path::new(&manifest_dir).join("data/context-capabilities.csv");

    println!(
        "cargo::rerun-if-changed={source}",
        source = source.display()
    );

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("context-capabilities.fst");

    let out = io::BufWriter::new(File::create(out_path).unwrap());
    let mut build = MapBuilder::new(out).unwrap();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(source)
        .unwrap();

    for record in rdr.records() {
        let record = record.unwrap();
        let context = record.get(0).unwrap();
        let capability = match record.get(1).unwrap() {
            "arbitrary" => 0,
            "structured" => 1,
            "fixed" => 2,
            _ => panic!("Unknown capability"),
        };

        build.insert(context, capability).unwrap();
    }

    build.finish().unwrap();
}

fn do_codeql_injection_sinks() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = Path::new(&manifest_dir).join("data/codeql-injection-sinks.json");
    let target = Path::new(&env::var("OUT_DIR").unwrap()).join("codeql-injection-sinks.json");

    print!(
        "cargo::rerun-if-changed={source}",
        source = source.display()
    );

    fs::copy(source, target).unwrap();
}

fn main() {
    do_context_capabilities();
    do_codeql_injection_sinks();
}
