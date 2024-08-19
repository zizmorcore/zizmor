use std::{io::stdout, path::Path};

use anyhow::{anyhow, Result};
use clap::Parser;

mod audit;
mod finding;
mod models;

/// A tool to detect "ArtiPACKED"-type credential disclosures in GitHub Actions.
#[derive(Parser)]
struct Args {
    /// The workflow filename or directory to audit.
    input: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input = &args.input;

    if !Path::new(&args.input).is_file() {
        return Err(anyhow!("TODO: support directory inputs"));
    }

    let workflow = models::Workflow::from_file(input)?;

    let findings = audit::artipacked(&workflow);

    if !findings.is_empty() {
        serde_json::to_writer_pretty(stdout(), &findings)?;
    }

    Ok(())
}
