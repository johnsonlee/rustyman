use clap::{Parser, Subcommand};
use rustyman::cert::CertificateAuthority;
use rustyman::config::Config;
use rustyman::proxy::ProxyServer;
use rustyman::web::WebServer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser)]
#[command(
    name = "rustyman",
    about = "A high-performance MITM proxy written in Rust",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Proxy listen address
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// Proxy listen port
    #[arg(short, long)]
    port: Option<u16>,

    /// Web UI port (0 to disable)
    #[arg(short, long)]
    web_port: Option<u16>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Log format (text, json)
    #[arg(long, default_value = "text")]
    log_format: String,

    /// Disable HTTPS MITM
    #[arg(long)]
    no_mitm: bool,

    /// CA certificate path
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// CA private key path
    #[arg(long)]
    ca_key: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate default configuration file
    Init {
        /// Output file path
        #[arg(short, long, default_value = "config.yaml")]
        output: PathBuf,
    },
    /// Generate CA certificate
    GenCa {
        /// Certificate output path
        #[arg(short, long, default_value = "~/.rustyman/ca.crt")]
        cert: String,
        /// Private key output path
        #[arg(short, long, default_value = "~/.rustyman/ca.key")]
        key: String,
    },
    /// Export CA certificate
    ExportCa {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = cli.command {
        return handle_command(command).await;
    }

    // Load or create configuration
    let mut config = if cli.config.exists() {
        info!("Loading configuration from {:?}", cli.config);
        Config::load(&cli.config)?
    } else {
        info!("Using default configuration");
        Config::default()
    };

    // Override config with CLI arguments
    if let Some(host) = cli.host {
        config.proxy.host = host;
    }
    if let Some(port) = cli.port {
        config.proxy.port = port;
    }
    if let Some(web_port) = cli.web_port {
        if web_port == 0 {
            config.web_ui.enabled = false;
        } else {
            config.web_ui.port = web_port;
        }
    }
    if cli.no_mitm {
        config.proxy.mitm_enabled = false;
    }
    if let Some(ca_cert) = cli.ca_cert {
        config.cert.ca_cert = ca_cert.to_string_lossy().to_string();
    }
    if let Some(ca_key) = cli.ca_key {
        config.cert.ca_key = ca_key.to_string_lossy().to_string();
    }

    config.logging.level = cli.log_level.clone();
    config.logging.format = cli.log_format.clone();

    // Expand paths
    config.expand_paths();

    // Setup logging
    setup_logging(&config)?;

    info!("Starting Rustyman MITM Proxy");

    // Initialize CA
    let ca = CertificateAuthority::new(
        &config.cert.ca_cert,
        &config.cert.ca_key,
        config.cert.auto_generate,
        config.cert.ca_validity_days,
        config.cert.cert_validity_days,
    )?;

    info!("CA certificate loaded/generated");

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();

    // Create proxy server
    let proxy = ProxyServer::new(config.clone(), ca)?;
    let state = proxy.state();

    // Start web UI if enabled
    let web_handle = if config.web_ui.enabled {
        let web_host = config.web_ui.host.clone();
        let web_port = config.web_ui.port;
        let web_state = Arc::clone(&state);
        let web_token = cancel_token.clone();

        Some(tokio::spawn(async move {
            let web_server = WebServer::new(web_state);
            if let Err(e) = web_server.run(&web_host, web_port, web_token).await {
                error!("Web UI error: {}", e);
            }
        }))
    } else {
        None
    };

    // Print startup info
    println!();
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║              🦀 Rustyman MITM Proxy                   ║");
    println!("╠═══════════════════════════════════════════════════════╣");
    println!(
        "║  Proxy:   http://{}:{:<24} ║",
        config.proxy.host, config.proxy.port
    );
    if config.web_ui.enabled {
        println!(
            "║  Web UI:  http://{}:{:<24} ║",
            config.web_ui.host, config.web_ui.port
        );
    }
    println!(
        "║  MITM:    {:<43} ║",
        if config.proxy.mitm_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!("╠═══════════════════════════════════════════════════════╣");
    println!("║  To trust the CA certificate:                         ║");
    println!("║  1. Download from Web UI or use --export-ca           ║");
    println!("║  2. Install to your system/browser trust store        ║");
    println!("║  Press Ctrl+C to stop the proxy                       ║");
    println!("╚═══════════════════════════════════════════════════════╝");
    println!();

    // Spawn signal handler
    let shutdown_token = cancel_token.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        info!("Received Ctrl+C, initiating graceful shutdown...");
        shutdown_token.cancel();
    });

    // Run proxy server
    proxy.run(cancel_token.clone()).await?;

    // Wait for web UI to finish if it was started
    if let Some(handle) = web_handle {
        let _ = handle.await;
    }

    info!("Rustyman stopped");
    Ok(())
}

async fn handle_command(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Init { output } => {
            info!("Creating default configuration at {:?}", output);
            Config::create_default(&output)?;
            println!("Configuration file created: {:?}", output);
            println!("\nEdit this file to customize your proxy settings.");
        }
        Commands::GenCa { cert, key } => {
            let cert_path = expand_tilde(&cert);
            let key_path = expand_tilde(&key);

            info!("Generating CA certificate");
            let _ca = CertificateAuthority::new(&cert_path, &key_path, true, 3650, 365)?;

            println!("CA certificate generated:");
            println!("  Certificate: {}", cert_path);
            println!("  Private key: {}", key_path);
            println!("\nInstall the certificate in your system/browser to trust HTTPS interception.");
        }
        Commands::ExportCa { output } => {
            let config = Config::default();
            let cert_path = expand_tilde(&config.cert.ca_cert);
            let key_path = expand_tilde(&config.cert.ca_key);

            let ca = CertificateAuthority::new(&cert_path, &key_path, true, 3650, 365)?;
            let pem = ca.ca_cert_pem();

            std::fs::write(&output, pem)?;
            println!("CA certificate exported to: {:?}", output);
        }
    }

    Ok(())
}

fn setup_logging(config: &Config) -> anyhow::Result<()> {
    let level = match config.logging.level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("hyper=warn".parse()?)
        .add_directive("rustls=warn".parse()?);

    if config.logging.format == "json" {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(false).with_thread_ids(false))
            .init();
    }

    Ok(())
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen('~', &home, 1);
        }
    }
    path.to_string()
}
