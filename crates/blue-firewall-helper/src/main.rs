mod commands;
mod helper;
mod state;

use anyhow::{bail, Result};
use commands::{verify_installed_helper, SystemRunner};
use helper::{read_input, require_root, Helper, Identity, Verb};
use state::State;

fn run() -> Result<()> {
    let identity = Identity::current();
    require_root(identity)?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let verb = Verb::parse(&args)?;
    verify_installed_helper()?;
    let policy = read_input(verb, &mut std::io::stdin().lock())?;
    let mut helper = Helper::new(State::system(), SystemRunner);
    println!("{}", helper.execute(identity, verb, policy)?);
    Ok(())
}

fn main() {
    if !cfg!(target_os = "linux") {
        eprintln!("Firewall helper requires Linux and systemd.");
        std::process::exit(1);
    }
    if let Err(error) = run() {
        // All errors are deliberately static: never print policy or command output.
        eprintln!("Firewall helper: {error}");
        std::process::exit(1);
    }
}

fn invalid_state<T>() -> Result<T> {
    bail!("Firewall state is invalid or insecure.")
}
