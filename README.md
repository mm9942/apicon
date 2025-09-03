# apicon

*Version 0.2.0*

Rust-based HTTP proxy gateway built on [Pingora](https://crates.io/crates/pingora), offering CORS handling, TLS termination, load‐balanced upstream routing, and secure privilege dropping.

## Features

* **Command‑line interface** (`main.rs`):

  * **Daemon mode** (`-d, --daemon`), PID file support (`--pid`).
  * **Privilege drop** to user/group after binding (`-u, --user`, `-g, --group`).
  * **Worker threads** (`-t, --threads`).
  * **TLS settings**: specify cert (`-c, --cert`), key (`-k, --key`), optional CA root (`--ca-root`).
  * **Logging**: `-l, --log <level> [file]` sets tracing level and optional log file; `--json` emits JSON logs.
  * **Endpoint config**: load upstream mapping from a TOML file via `--config`.

* **HTTP Proxy service**:

  * Implements `ProxyHttp` trait for custom routing logic.
  * **CORS preflight** and response header filters.
  * Configurable allowed origins via the TOML config or `--allow-origin`.
  * **Load balancing** via `pingora::lb::LoadBalancer<RoundRobin>`.
  * Backend selection based on request path or round‑robin over a pool.
  * Each backend may specify an SNI hostname in `apicon.toml`.
  * Outbound connections bind to the listener's address family for IPv4/IPv6.
  * Optional per-endpoint connection and read timeouts.

* **TLS termination**:

  * Uses `pingora_core::listeners::tls::TlsSettings` for intermediate security profile.
  * Supports HTTP/2 (h2) on TLS ports.
  * Optional **mutual TLS** via `--client-ca` and `--require-client-cert`.
    Use `apicon mtls` to generate sample certificates for testing.

* **Error handling** (`error.rs`):

  * Local `ProxErr` enum wrapping I/O, DNS resolution, Pingora errors, transport errors, and plain strings.
  * Conversion helpers to `Box<pingora::Error>` for trait compatibility (`into_pg`, `to_pg_error`).
  * Alias `ProxResult<T>` for concise error returns.

* **Advanced capabilities**:

  * **OCSP stapling** to speed up TLS handshakes and improve certificate validation.
  * **EWMA load balancing** with connection pooling for smoother upstream routing.
  * Built-in **telemetry metrics** for monitoring runtime behavior.
  * Enhanced handshake logs indicate OCSP stapling and session ticket issuance/resumption.

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

### Service subcommand

`apicon service [--start|--restart|--stop|--status] --name <svc> [--name <svc>...] [--workingdir <dir>]`

Creates `/etc/systemd/system/<svc>.service` for each `--name`. The unit uses the provided working directory, user and group. Without `--start` etc. it installs and enables all units; the flags manage each specified unit via `systemctl`.

### MTLS subcommand

`apicon mtls --out ./certs`

Generates a minimal CA along with server and client certificates for testing mutual TLS.

### Example `apicon.toml`

```toml
listener = "[::]:443"
cert = "/path/fullchain.pem"
key  = "/path/privkey.pem"
ca_root = "/path/ca.pem"
allow_origin = ["https://example.com"]
base_prefix = "/api"
prepend_base_prefix = true

[[lb_backends]]
addr = "127.0.0.1:443"
sni = "m.mm29942.com"

[[endpoint]]
prefix = "leads"  # resolved as /api/leads
addr = "127.0.0.1:6443"
tls = true
sni = "m.mm29942.com"

[[endpoint]]
prefix = "/support"  # absolute path
addr = "127.0.0.1:9443"
tls = true
sni = "m.mm29942.com"
```

When `prepend_base_prefix` is enabled, endpoint prefixes that do not start with
`/` are treated as relative to `base_prefix`. Prefixes beginning with `/` remain
absolute.

## Metrics configuration

Enable a Prometheus metrics endpoint by adding a `[metrics]` table to `apicon.toml`:

```toml
[metrics]
addr = "127.0.0.1:9100"
# path defaults to "/metrics"
```

When present, a separate HTTP server publishes runtime metrics at the configured address and path.

## sysapicon

`sysapicon` is a companion controller that manages the `apicon` systemd
service. It wraps common `systemctl` operations and reports structured logs via
[`tracing`](https://crates.io/crates/tracing). Compile the Rust binary once and
place it in your `PATH`:

```bash
cargo install --path sysapicon
```

```bash
# enable and start apicon
sysapicon --start
# disable and stop apicon
sysapicon --stop
# restart the service
sysapicon --restart
# reload unit files and restart
sysapicon --reload
# stream structured logs from journald
sysapicon --log
```

## Module Overview

### `main.rs`

* **PID file helpers**: `open_pid`, `write_pid` with proper file modes.
* **Service file generator**: `create_service` writes `/etc/systemd/system/<name>.service` for each configured unit.
* **Privilege resolution**: `resolve_ids` maps user/group names to UID/GID using `users` crate.
* **CORS origin configuration** via the TOML config or `--allow-origin` flags.
* **Logging**: `init_tracing(level, json, file)` configures `tracing_subscriber`.
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
Run `cargo clippy -- -D warnings` after making changes to keep the codebase
lint-free and consistent with project conventions.

```bash
# Build release
cargo build --release
# Run tests (if any)
cargo test
# Lint & format
cargo fmt -- --check
cargo clippy -- -D warnings
```

## Memory Allocator Options

Enable alternative global allocators at build time:

```bash
cargo build --features jemalloc
cargo build --features mimalloc
```

Only one allocator feature can be enabled; without either feature the system allocator is used.

### Benchmark

Latency for allocating a 1 KiB vector (`criterion`):

| allocator | median time |
|-----------|-------------|
| system    | 705 ns |
| jemalloc  | 675 ns |
| mimalloc  | 678 ns |
