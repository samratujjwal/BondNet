//! `bondnet-server` binary: parse CLI, warn about plaintext, run.

use std::sync::Arc;

use bondnet_server::{Server, parse_args, print_setup_guide};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = match parse_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!(
                "usage: bondnet-server [--bind ADDR:PORT] [--verbose] [--tun-name NAME --tun-addr IP --tun-prefix N] [--wan-iface NAME] [--print-setup]"
            );
            std::process::exit(2);
        }
    };

    // Day 10: print the explicit administrator setup commands (TUN
    // address, forwarding, NAT) and exit without binding anything.
    if config.print_setup {
        let tun = config
            .tun_config()
            .expect("parse_args already validated TUN flags");
        let mut out = String::new();
        // fmt::Write on String cannot fail; the expect documents that.
        print_setup_guide(tun.as_ref(), config.wan_interface.as_deref(), &mut out)
            .expect("writing the setup guide to a String cannot fail");
        print!("{out}");
        return;
    }

    // Day 20: the warning reflects the actual configuration. With --psk,
    // DATA is authenticated-encrypted in both directions; without it,
    // traffic is plaintext.
    if config.psk.is_some() {
        println!("encryption: ENABLED (XChaCha20-Poly1305, PSK from --psk)");
    } else {
        println!(
            "WARNING: no --psk given, traffic is plaintext. Development use only — not a production VPN server."
        );
    }

    let server = Arc::new(Server::new(config));
    let shutdown = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to listen for Ctrl+C: {error}; running until killed");
            std::future::pending::<()>().await;
        }
    };
    if let Err(error) = server.run(shutdown).await {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}
