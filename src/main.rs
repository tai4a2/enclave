//! Binary entry point.

use clap::Parser;

use enclave::cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = enclave::cli::run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
