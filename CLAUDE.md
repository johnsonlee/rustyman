# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

## Project Overview

Rustyman is a high-performance MITM (Man-In-The-Middle) HTTP/HTTPS proxy written in Rust — the core infrastructure for **feedback loop driven AI-assisted engineering**.

### Why Rustyman Exists

Rustyman is not "a faster mitmproxy." It is purpose-built infrastructure that enables AI agents to participate in a closed-loop engineering workflow: **configure → execute → observe → adjust**. The entire architecture serves this feedback loop:

- **REST API** — the control plane for AI agents to programmatically set up mock rules (Map Local), redirect traffic (Map Remote), rewrite headers, and query traffic records, all without human intervention.
- **SSE real-time event stream** (`/api/events`) — the observation channel. The primary consumer is not a human watching a browser, but an AI agent that needs structured, machine-readable feedback on HTTP traffic (request sent? response correct? status code? headers?) to decide its next action.
- **Single binary, zero dependencies** — designed for frictionless integration into CI/CD pipelines and automated test environments. An AI-driven workflow can spin up a proxy instance, run tests, collect feedback, and tear it down with no environment setup.
- **Declarative YAML configuration** — machine-writable, version-controllable, no imperative scripting required.

```
AI Agent
  │
  ├──▶ Configure rules (REST API)     ← Control plane
  ├──▶ Trigger tests                   ← Execution
  ├──◀ SSE real-time traffic events    ← Observation / Feedback
  └──▶ Adjust based on feedback        ← Closed-loop iteration
```

### How This Differs from mitmproxy

mitmproxy is designed for humans — TUI interaction, Python scripting, manual inspection. Rustyman is designed for **AI agents as first-class consumers**: machine-readable APIs, structured event streams, declarative configuration, and stateless deployment. This is the fundamental difference.

## Build Commands

```bash
# Build debug version
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Run with default settings
cargo run

# Check code without building
cargo check

# Format code
cargo fmt

# Run clippy lints
cargo clippy
```

## Project Architecture

```
src/
├── main.rs              # CLI entry point with clap argument parsing
├── lib.rs               # Library exports
├── cert/mod.rs          # CA certificate generation for MITM (rcgen)
├── config/mod.rs        # YAML configuration parsing (serde_yaml)
├── proxy/
│   ├── mod.rs           # Proxy server orchestration
│   ├── handler.rs       # HTTP/HTTPS request handling (hyper)
│   └── tls.rs           # TLS acceptor for MITM (tokio-rustls)
├── rules/
│   ├── mod.rs           # Rule engine combining all rules
│   ├── map_remote.rs    # URL redirect rules with regex
│   ├── map_local.rs     # Local file serving rules
│   └── header.rs        # Header rewrite rules with regex
├── traffic/mod.rs       # Traffic recording & broadcast channel
└── web/
    ├── mod.rs           # Web UI server (axum)
    ├── api.rs           # REST API endpoints + SSE traffic streaming
    └── websocket.rs     # Legacy WebSocket support

static/                  # Web UI frontend files
├── index.html
├── app.js
└── style.css
```

## Key Dependencies

- **tokio** - Async runtime
- **hyper** / **hyper-util** - HTTP client/server
- **axum** - Web framework for API and WebSocket
- **tokio-rustls** / **rustls** - TLS implementation
- **rcgen** - X.509 certificate generation
- **regex** - Pattern matching for rules
- **serde** / **serde_yaml** - Configuration serialization
- **clap** - Command-line argument parsing
- **tracing** - Logging and diagnostics

## Core Concepts

### MITM Flow
1. Client connects to proxy
2. For HTTPS (CONNECT method):
   - Proxy generates certificate for target domain signed by CA
   - Establishes TLS with client using generated cert
   - Forwards decrypted traffic to target server
3. Rules (Map Remote, Map Local, Header) are applied
4. Traffic is recorded and broadcast via SSE endpoint (`/api/events`)

### Rule Priority
1. **Map Local** - Checked first, serves local files if matched
2. **Map Remote** - Redirects to different URLs if matched
3. **Header Rules** - Applied to both requests and responses

### Configuration
- YAML-based configuration in `config.yaml`
- Runtime reloading via API (`POST /api/rules/reload`)
- CLI flags override config file values

## Testing

```bash
# Run all tests
cargo test

# Run specific test module
cargo test cert::tests
cargo test rules::tests
```

## Common Development Tasks

### Adding a New Rule Type
1. Create new file in `src/rules/`
2. Implement handler struct with `new()` and `match_url()` methods
3. Add to `RuleEngine` in `src/rules/mod.rs`
4. Add config struct in `src/config/mod.rs`
5. Add API endpoints in `src/web/api.rs`

### Modifying Certificate Generation
- Certificate logic is in `src/cert/mod.rs`
- Uses rcgen 0.12 API with `Certificate::from_params()`
- Certificates are cached per-domain in memory

### Adding Web UI Features
- API endpoints in `src/web/api.rs`
- WebSocket events in `src/web/websocket.rs`
- Frontend files in `static/` (embedded at compile time)

## Notes

- CA certificate is auto-generated on first run at `~/.rustyman/ca.crt`
- Real-time traffic streaming via SSE endpoint: `GET /api/events`
- Web UI uses EventSource API for real-time traffic updates
- Traffic entries are stored in memory (configurable max entries)
- The proxy handles both HTTP and HTTPS traffic on the same port

## Real-time Traffic Streaming

The `/api/events` SSE endpoint streams traffic events as JSON:

```bash
# Consume events via curl
curl -N http://localhost:8081/api/events

# Filter with jq
curl -N http://localhost:8081/api/events | grep "^data:" | jq -R 'fromjson?'
```

Event types:
- `request` - New HTTP request received
- `response` - Response received from server
- `completed` - Request/response cycle complete
- `cleared` - Traffic log cleared

Multiple consumers can connect simultaneously (broadcast channel).
