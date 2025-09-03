# Development Workflow

This project uses Rust's standard tooling to verify code before changes are merged.

## Local Verification

Run the following commands before submitting a pull request:

```bash
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
```

`cargo fmt` ensures the code is formatted consistently, `cargo clippy` enforces
lint checks without allowing warnings, and `cargo test` runs the test suite.

## Continuous Integration

GitHub Actions runs the same commands for every push and pull request. Any
failure will mark the workflow as failed, preventing the change from being
merged until the issue is resolved.
