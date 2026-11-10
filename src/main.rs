mod ad;
mod backend;
mod ber;
mod cli;
mod commands;
mod config;
mod discovery;
mod error;
mod escape;
mod filter;
mod ldif;
mod model;
mod output;
mod policy;
mod secret;
mod template;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let code = match commands::run(cli) {
        Ok(()) => 0,
        Err(error::Error::CompareFalse) => 1,
        Err(e) => {
            eprintln!("ldap: {e}");
            if let error::Error::Auth(m) | error::Error::Ldap { message: m, .. } = &e {
                if let Some(hint) = error::ad_bind_hint(m) {
                    eprintln!("ldap: Active Directory says: {hint}");
                }
            }
            e.exit_code()
        }
    };
    std::process::exit(code);
}
