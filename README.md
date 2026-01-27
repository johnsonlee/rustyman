# Rustyman

A high-performance MITM (Man-In-The-Middle) proxy written in Rust, inspired by [mitmproxy](https://mitmproxy.org/).

## Features

- **HTTP/HTTPS Proxy with MITM** - Intercept and inspect encrypted HTTPS traffic
- **Map Remote** - Redirect requests to different servers using regex patterns
- **Map Local** - Serve local files for matching requests
- **Header Rewrite** - Add, remove, or modify HTTP headers with regex support
- **YAML Configuration** - Easy-to-read configuration format
- **Web UI** - Real-time traffic monitoring and rule management
- **CLI** - Command-line interface with logging options

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/johnsonlee/rustyman.git
cd rustyman

# Build release binary
cargo build --release

# The binary will be at target/release/rustyman
```

### Requirements

- Rust 1.75+

## Quick Start

1. **Start the proxy:**

```bash
# With default settings (proxy on :8080, web UI on :8081)
rustyman

# With custom ports
rustyman --port 9090 --web-port 9091

# With configuration file
rustyman --config config.yaml
```

2. **Configure your browser/system to use the proxy:**
   - HTTP Proxy: `127.0.0.1:8080`
   - HTTPS Proxy: `127.0.0.1:8080`

3. **Install the CA certificate:**
   - Open Web UI at `http://127.0.0.1:8081`
   - Click "Download CA Cert"
   - Install the certificate in your system/browser trust store

4. **Browse the web and monitor traffic in the Web UI**

## Command Line Options

```
rustyman [OPTIONS] [COMMAND]

Options:
  -c, --config <FILE>     Configuration file path [default: config.yaml]
  -H, --host <HOST>       Proxy listen address
  -p, --port <PORT>       Proxy listen port
  -w, --web-port <PORT>   Web UI port (0 to disable)
  -l, --log-level <LEVEL> Log level (trace, debug, info, warn, error) [default: info]
      --log-format <FMT>  Log format (text, json) [default: text]
      --no-mitm           Disable HTTPS MITM
      --ca-cert <PATH>    CA certificate path
      --ca-key <PATH>     CA private key path
  -h, --help              Print help
  -V, --version           Print version

Commands:
  init       Generate default configuration file
  gen-ca     Generate CA certificate
  export-ca  Export CA certificate
```

## Configuration

Create a `config.yaml` file (or use `rustyman init` to generate one):

```yaml
# Proxy settings
proxy:
  host: "127.0.0.1"
  port: 8080
  mitm_enabled: true

# Web UI
web_ui:
  enabled: true
  host: "127.0.0.1"
  port: 8081

# Map Remote - redirect requests
map_remote:
  - name: "api-to-staging"
    enabled: true
    pattern: "https://api\\.prod\\.com/(.*)"
    target: "https://api.staging.com/$1"
    preserve_path: false
    preserve_query: true

# Map Local - serve local files
map_local:
  - name: "mock-api"
    enabled: true
    pattern: "https://api\\.example\\.com/users"
    local_path: "/path/to/mock/users.json"
    mime_type: "application/json"

# Header rewrite rules
header_rules:
  - name: "add-auth"
    enabled: true
    url_pattern: "https://api\\.example\\.com/.*"
    apply_to_request: true
    apply_to_response: false
    operations:
      - action: add
        name: "Authorization"
        value: "Bearer token123"
```

See [config.example.yaml](config.example.yaml) for a complete example.

## Map Remote

Redirect HTTP/HTTPS requests to different servers:

```yaml
map_remote:
  # Simple redirect
  - name: "redirect-api"
    pattern: "https://api\\.prod\\.com/.*"
    target: "https://api.staging.com"
    preserve_path: true
    preserve_query: true

  # With regex capture groups
  - name: "version-rewrite"
    pattern: "https://api\\.example\\.com/v(\\d+)/(.*)"
    target: "https://api.example.com/v2/$2"
```

## Map Local

Serve local files for matching requests:

```yaml
map_local:
  # Single file
  - name: "mock-users"
    pattern: "https://api\\.example\\.com/users$"
    local_path: "/mocks/users.json"

  # Directory mapping with capture groups
  - name: "local-assets"
    pattern: "https://cdn\\.example\\.com/assets/(.*)"
    local_path: "/local/assets/$1"
```

## Header Rewrite

Modify HTTP headers with regex support:

```yaml
header_rules:
  # Add header
  - name: "add-header"
    url_pattern: ".*"
    operations:
      - action: add
        name: "X-Custom-Header"
        value: "my-value"

  # Remove header
  - name: "remove-cookies"
    url_pattern: ".*"
    operations:
      - action: remove
        name: "Cookie"

  # Remove headers by pattern
  - name: "remove-x-headers"
    url_pattern: ".*"
    operations:
      - action: remove
        name: "X-*"  # Wildcard pattern

  # Modify header value with regex
  - name: "modify-ua"
    url_pattern: ".*"
    operations:
      - action: modify
        name: "User-Agent"
        value_pattern: "Chrome/\\d+"
        replacement: "Chrome/999"
```

## Web UI

The Web UI provides:

- **Traffic View** - Real-time request/response monitoring with search
- **Rules Management** - Add/edit Map Remote, Map Local, and Header rules
- **Settings** - View proxy configuration and statistics
- **CA Certificate Download** - Easy certificate export

Access at `http://127.0.0.1:8081` (default)

## API Endpoints

The Web UI exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/traffic` | GET | List traffic entries |
| `/api/traffic/:id` | GET | Get single traffic entry |
| `/api/traffic/clear` | POST | Clear all traffic |
| `/api/traffic/search?q=` | GET | Search traffic by URL |
| `/api/config` | GET/POST | Get/update configuration |
| `/api/rules/map-remote` | GET/POST | Get/add map remote rules |
| `/api/rules/map-local` | GET/POST | Get/add map local rules |
| `/api/rules/header` | GET/POST | Get/add header rules |
| `/api/rules/reload` | POST | Reload rules from config |
| `/api/ca/cert` | GET | Download CA certificate |
| `/api/stats` | GET | Get proxy statistics |
| `/ws/traffic` | WS | WebSocket for real-time traffic |

## Installing the CA Certificate

### macOS

```bash
# Export the certificate
rustyman export-ca -o rustyman-ca.crt

# Add to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rustyman-ca.crt
```

### Linux (Ubuntu/Debian)

```bash
# Export the certificate
rustyman export-ca -o rustyman-ca.crt

# Install
sudo cp rustyman-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### Windows

1. Export the certificate: `rustyman export-ca -o rustyman-ca.crt`
2. Double-click the .crt file
3. Click "Install Certificate"
4. Select "Local Machine" → "Place all certificates in the following store"
5. Browse → "Trusted Root Certification Authorities"
6. Finish the wizard

### Firefox

Firefox uses its own certificate store:
1. Open Firefox Settings → Privacy & Security → Certificates → View Certificates
2. Import the CA certificate
3. Check "Trust this CA to identify websites"

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  Rustyman   │────▶│   Server    │
│  (Browser)  │◀────│   Proxy     │◀────│  (Target)   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │             │
              ┌─────▼─────┐ ┌─────▼─────┐
              │  Web UI   │ │  Traffic  │
              │  (Axum)   │ │  Storage  │
              └───────────┘ └───────────┘
```

## Development

```bash
# Run in development mode
cargo run

# Run tests
cargo test

# Format code
cargo fmt

# Run clippy lints
cargo clippy
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
