# apicon

Rust-based HTTP proxy gateway built on [Pingora](https://crates.io/crates/pingora), offering CORS handling, TLS termination, load‐balanced upstream routing, and secure privilege dropping.

## Features

* **Command‑line interface** (`main.rs`):

  * **Daemon mode** (`-d, --daemon`), PID file support (`--pid`).
  * **Privilege drop** to user/group after binding (`-u, --user`, `-g, --group`).
  * **Worker threads** (`-t, --threads`).
  * **TLS settings**: specify cert (`-c, --cert`), key (`-k, --key`), optional CA root (`--ca-root`).
    Certificates may also be defined per `[[gateway]]` using `cert`, `key` and `sni`.
  * **Logging**: `-l, --log <level> [file]` sets tracing level and optional log file; `--json` emits JSON logs.
  * **Endpoint config**: load upstream mapping from a TOML file via `--config`.
  * **Multiple gateways** via repeated `[[gateway]]` sections in the config. Each gateway specifies its own `sni` and certificates.
  * **Static file servers** via optional `[gateway.web]` table.

* **HTTP Proxy service**:

  * Implements `ProxyHttp` trait for custom routing logic.
  * **CORS preflight** and response header filters.
  * Configurable allowed origins via the TOML config or `--allow-origin`.
  * Configurable allowed headers via the TOML config or `--allow-header`.
  * **Load balancing** via `pingora::lb::LoadBalancer<RoundRobin>`.
  * Backend selection based on request path or round‑robin over a pool.
  * Each backend may specify an SNI hostname in `apicon.toml`.
  * Outbound connections bind to the listener's address family for IPv4/IPv6.

* **TLS termination**:

  * Uses `pingora_core::listeners::tls::TlsSettings` for intermediate security profile.
  * Supports HTTP/2 (h2) on TLS ports.
  * Optional **mutual TLS** via `--client-ca` and `--require-client-cert`.
    Use `apicon mtls` to generate sample certificates for testing.

* **Error handling** (`error.rs`):

  * Local `ProxErr` enum wrapping I/O, DNS resolution, Pingora errors, transport errors, and plain strings.
  * Conversion helpers to `Box<pingora::Error>` for trait compatibility (`into_pg`, `to_pg_error`).
  * Alias `ProxResult<T>` for concise error returns.

## Installation

```bash
# Install Rust toolchain (1.70+)
git clone <repo_url>
cd apicon
cargo build --release
# Binary at target/release/apicon
```

## Configuration & Usage

```bash
# Basic startup
target/release/apicon \
  --cert /path/fullchain.pem \
  --key  /path/privkey.pem \
  --ca-root /path/ca.pem \
  --threads 8 \
  --pid /var/run/apicon.pid \
  -l debug /var/log/apicon.log --json \
  --config /etc/apicon.toml \
  --allow-origin https://example.com
  # mTLS example
  --client-ca ./certs/ca.pem --require-client-cert

# Install and start systemd unit
sudo apicon service --user www-data --group www-data --workingdir /opt/apicon --name api1 --name api2
```

On startup, the proxy will:

1. Initialize structured logging with `tracing_subscriber`.
2. Create/truncate the PID file.
3. `apicon service` installs `/etc/systemd/system/<name>.service` for each specified unit and enables them.
4. Bootstrap `pingora::Server` with thread pool and options.
5. Configure TLS listener and attach HTTP proxy service.
6. Optionally drop privileges to configured user/group.
7. Enter the request loop (`run_forever`).

## CLI Reference

| Option               | Type           | Default               | Description                                  |
| -------------------- | -------------- | --------------------- | -------------------------------------------- |
| `-d`, `--daemon`     | flag           | `false`               | Run in background daemon mode. |
| `--pid <path>`       | `PathBuf`      | `/run/pingora-gw.pid` | Path to PID file.                            |
| `-u, --user <name>`  | `String`       | —                     | Drop process to this user after bind.        |
| `-g, --group <name>` | `String`       | —                     | Drop process to this group after bind.       |
| `-t, --threads <n>`  | `usize`        | `4`                   | Number of worker threads.                    |
| `-c, --cert <path>`  | `PathBuf`      | TLS certificate file. |                                              |
| `-k, --key <path>`   | `PathBuf`      | TLS private key file. |                                              |
| `--ca-root <path>`   | `Option<Path>` | none                  | Optional CA root bundle.                     |
| `--client-ca <path>` | `Option<Path>` | none                  | CA certificate for client auth.             |
| `--require-client-cert` | flag        | `false`               | Enforce client certificates (mTLS).        |
| `-l, --log <level> [file]` | `Vec<String>` | `[info]`              | Log level and optional log file path. |
| `--json`             | flag           | `false`               | Emit JSON‑formatted logs.                    |
| `--config <path>`    | `PathBuf`     | —                     | Load endpoint definitions from a TOML file.  |
| `--allow-origin <host>` | `String`     | —                     | Allowed CORS origin (repeatable, overrides config). |
| `--allow-header <name>` | `String`     | —                     | Allowed CORS header (repeatable, overrides config). |

### Service subcommand

`apicon service [--start|--restart|--stop|--status] --name <svc> [--name <svc>...] [--workingdir <dir>]`

Creates `/etc/systemd/system/<svc>.service` for each `--name`. The unit uses the provided working directory, user and group. Without `--start` etc. it installs and enables all units; the flags manage each specified unit via `systemctl`.

### MTLS subcommand

`apicon mtls --out ./certs`

Generates a minimal CA along with server and client certificates for testing mutual TLS.

### Example `apicon.toml`

The configuration may define multiple `[[gateway]]` sections to run several
listeners at once.

```toml
ca_root = "/path/ca.pem"

[[gateway]]
listener = "[::]:443"
cert = "/path/fullchain.pem"
key  = "/path/privkey.pem"
sni = "example.com"
allow_headers = ["Content-Type", "Authorization"]

  [gateway.web]
  listener = "[::]:8080"
  dir = "/srv/www/site1"

  [[gateway.endpoint]]
  prefix = "/leads"
  addr = "127.0.0.1:6443"
  tls = true

[[gateway]]
listener = "[::]:8443"
cert = "/path/second/fullchain.pem"
key  = "/path/second/privkey.pem"
sni = "other.com"
allow_headers = ["Content-Type", "Authorization"]

  [gateway.web]
  listener = "[::]:8081"
  dir = "/srv/www/site2"

  [[gateway.endpoint]]
  prefix = "/api"
  addr = "127.0.0.1:5000"
  tls = false
```

## Module Overview

### `main.rs`

* **PID file helpers**: `open_pid`, `write_pid` with proper file modes.
* **Service file generator**: `create_service` writes `/etc/systemd/system/<name>.service` for each configured unit.
* **Privilege resolution**: `resolve_ids` maps user/group names to UID/GID using `users` crate.
* **CORS origin configuration** via the TOML config or `--allow-origin` flags.
* **CORS header configuration** via the TOML config or `--allow-header` flags.
* **Logging**: `init_tracing(level, json, file)` configures `tracing_subscriber` with optional file output.
* **Config loading**: `load_config` parses endpoint mappings from a TOML file.
* **Proxy service bootstrap**:

  1. Parse CLI into `Cli` struct (Clap derive).
  2. Prepare `ServerConf` (threads, pid, ca\_file, etc.).
  3. Create `Server` and `http_proxy_service`.
  4. Add TLS listener and proxy service.
  5. Write PID and drop privileges.
  6. `server.run_forever()`.

### `error.rs`

* Defines `ProxErr` and conversion traits to/from `io::Error`, `pingora::Error`, `String`.
* Implements `Display` and `Error` for rich diagnostics.
* Provides `into_pg` and `to_pg_error` for Pingora trait compatibility.
* Alias `ProxResult<T>` for `Result<T, ProxErr>`.

### Proxy Logic (`ProxyHttp` impl)

* **CORS preflight**: `respond_preflight` sets `Access-Control-Allow-*` headers.
* **Upstream selection**: custom routing in `upstream_peer` based on request path or round‑robin.
* **Request/response filters**: modify headers (`Host`, CORS expose headers).

## Dependencies

```toml
[dependencies]
async-trait = "0.1"
bytes       = "1"
clap        = { version = "4.5", features = ["derive"] }
nix         = { version = "0.27", features = ["user"] }
pingora     = { version = "0.5", features = ["lb","boringssl"] }
pingora-core = { version = "0.5", features = ["boringssl"] }
pingora-proxy = { version = "0.5", features = ["boringssl"] }
pingora-http = "0.5"
users       = "0.11"
tracing     = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter","fmt","json"] }
```

## Development & Testing

```bash
# Build release
cargo build --release
# Run tests (if any)
cargo test
# Lint & format
cargo fmt -- --check
cargo clippy -- -D warnings
```
