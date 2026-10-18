//! Day 13: two-path diagnostic.
//!
//! ```text
//! bondnet-client path-diag --session-id 1001 \
//!   --path1-id 1 --path1-local 192.168.1.10:0 --path1-remote VPS:51820 \
//!   --path2-id 2 --path2-local 192.168.2.10:0 --path2-remote VPS:51820 \
//!   [--path1-name NAME] [--path2-name NAME] [--path2-disabled] [--verbose]
//! ```
//!
//! Initializes two independent physical paths, reports each path's
//! configured ID and actual bound local/remote endpoints, sends one
//! harmless `PathHello` from each (the existing control packet type —
//! the server records it via its normal observation path), then shuts
//! both down cleanly.
//!
//! This proves the CLIENT can create two independent transports. It does
//! NOT prove the server received anything — check the server's verbose
//! log for the matching `RX ... type=PathHello` lines. A second socket
//! bound to another local IP is not proof of two independent Internet
//! connections; see docs/day13-test-guide.md.

use bondnet_client::{PathManager, PhysicalPathConfig};
use bondnet_protocol::PacketType;

struct DiagArgs {
    session_id: u64,
    path1: PhysicalPathConfig,
    path2: PhysicalPathConfig,
    verbose: bool,
}

fn parse_path_args(
    args: &[String],
    prefix: &str,
    default_name: &str,
) -> Result<PhysicalPathConfig, String> {
    let mut name = default_name.to_string();
    let mut path_id: Option<u16> = None;
    let mut local: Option<std::net::SocketAddr> = None;
    let mut remote: Option<std::net::SocketAddr> = None;
    let mut enabled = true;

    let flag = |key: &str| format!("--{prefix}-{key}");
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == &flag("name") {
            name = rest
                .next()
                .ok_or_else(|| format!("{} requires a name", flag("name")))?
                .clone();
        } else if arg == &flag("id") {
            let v = rest
                .next()
                .ok_or_else(|| format!("{} requires a number", flag("id")))?;
            path_id = Some(
                v.parse()
                    .map_err(|_| format!("invalid {}: {v}", flag("id")))?,
            );
        } else if arg == &flag("local") {
            let v = rest
                .next()
                .ok_or_else(|| format!("{} requires an address", flag("local")))?;
            local = Some(
                v.parse()
                    .map_err(|_| format!("invalid {}: {v}", flag("local")))?,
            );
        } else if arg == &flag("remote") {
            let v = rest
                .next()
                .ok_or_else(|| format!("{} requires an address", flag("remote")))?;
            remote = Some(
                v.parse()
                    .map_err(|_| format!("invalid {}: {v}", flag("remote")))?,
            );
        } else if arg == &flag("disabled") {
            enabled = false;
        }
    }

    Ok(PhysicalPathConfig {
        name,
        path_id: path_id.ok_or_else(|| format!("{} is required", flag("id")))?,
        local_addr: local.ok_or_else(|| format!("{} is required", flag("local")))?,
        remote_addr: remote.ok_or_else(|| format!("{} is required", flag("remote")))?,
        enabled,
    })
}

fn parse_diag_args(args: &[String]) -> Result<DiagArgs, String> {
    let mut session_id: Option<u64> = None;
    let mut verbose = false;
    let mut rest_args: Vec<String> = Vec::new();

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--session-id" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--session-id requires a number".to_string())?;
                session_id = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --session-id: {v}"))?,
                );
            }
            "--verbose" => verbose = true,
            _ => rest_args.push(arg.clone()),
        }
    }

    Ok(DiagArgs {
        session_id: session_id.ok_or_else(|| "--session-id is required".to_string())?,
        path1: parse_path_args(&rest_args, "path1", "primary")?,
        path2: parse_path_args(&rest_args, "path2", "secondary")?,
        verbose,
    })
}

/// Run the two-path diagnostic. `args` are the CLI words after `path-diag`.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_diag_args(args).map_err(|e| {
        format!(
            "{e}\nusage: bondnet-client path-diag --session-id N \
             --path1-id N --path1-local ADDR:PORT --path1-remote ADDR:PORT \
             --path2-id N --path2-local ADDR:PORT --path2-remote ADDR:PORT \
             [--path1-name NAME] [--path2-name NAME] [--path2-disabled] [--verbose]"
        )
    })?;

    println!("WARNING: BondNet Day 13 is plaintext (no encryption yet). Development use only.");

    let mut manager = PathManager::new(vec![parsed.path1, parsed.path2])
        .map_err(|e| format!("invalid path configuration: {e}"))?;
    manager.initialize(parsed.session_id).await;

    for status in manager.status() {
        println!(
            "path \"{}\" id={} enabled={} initialized={} local={} remote={}{}",
            status.name,
            status.path_id,
            status.enabled,
            status.initialized,
            status
                .local_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".to_string()),
            status.remote_addr,
            status
                .init_error
                .as_ref()
                .map(|e| format!(" error={e}"))
                .unwrap_or_default(),
        );
    }

    // Harmless diagnostic: one PathHello per initialized path. The server
    // records these via its normal observation path (Day 6); check its
    // verbose log for the matching lines.
    for status in manager.status() {
        if !status.initialized {
            continue;
        }
        let path = manager
            .get(status.path_id)
            .expect("initialized path is present");
        match path.send_new(PacketType::PathHello, Vec::new()).await {
            Ok(sequence) => println!(
                "path \"{}\" id={}: PathHello sent seq={sequence}",
                status.name, status.path_id,
            ),
            Err(error) => {
                if parsed.verbose {
                    eprintln!(
                        "path \"{}\" id={}: PathHello send failed: {error}",
                        status.name, status.path_id,
                    );
                }
            }
        }
    }

    manager.shutdown_all();
    println!("path-diag complete: both paths shut down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn full() -> Vec<String> {
        args(&[
            "--session-id",
            "1001",
            "--path1-id",
            "1",
            "--path1-local",
            "127.0.0.1:0",
            "--path1-remote",
            "127.0.0.1:51820",
            "--path2-id",
            "2",
            "--path2-local",
            "127.0.0.1:0",
            "--path2-remote",
            "127.0.0.1:51820",
        ])
    }

    #[test]
    fn full_diag_args_parse() {
        let parsed = parse_diag_args(&full()).unwrap();
        assert_eq!(parsed.session_id, 1001);
        assert_eq!(parsed.path1.path_id, 1);
        assert_eq!(parsed.path2.path_id, 2);
        assert_eq!(parsed.path1.name, "primary");
        assert!(parsed.path1.enabled);
        assert!(parsed.path2.enabled);
    }

    #[test]
    fn duplicate_ids_rejected() {
        let mut a = full();
        // Change --path2-id 2 to 1.
        let pos = a.iter().position(|s| s == "2").unwrap();
        a[pos] = "1".to_string();
        let parsed = parse_diag_args(&a).unwrap();
        assert!(PathManager::new(vec![parsed.path1, parsed.path2]).is_err());
    }

    #[test]
    fn path2_disabled_parses() {
        let mut a = full();
        a.push("--path2-disabled".to_string());
        let parsed = parse_diag_args(&a).unwrap();
        assert!(!parsed.path2.enabled);
    }

    #[test]
    fn missing_session_id_rejected() {
        let a = args(&[
            "--path1-id",
            "1",
            "--path1-local",
            "127.0.0.1:0",
            "--path1-remote",
            "127.0.0.1:51820",
            "--path2-id",
            "2",
            "--path2-local",
            "127.0.0.1:0",
            "--path2-remote",
            "127.0.0.1:51820",
        ]);
        assert!(parse_diag_args(&a).is_err());
    }
}
