# Development

## Repo layout

```
moatd/
├── crates/
│   ├── moatd-common/   # shared wire types, no_std
│   ├── moatd-ebpf/     # eBPF program (XDP + TC)
│   └── moatd/          # userspace crate; builds `moatd` and `moat` binaries
├── book/               # this book
├── dist/               # systemd unit, modules-load.d
├── tests/integration/  # netns-based integration tests
├── .github/workflows/  # CI
├── Cargo.toml          # workspace
├── Makefile
└── README.md
```

## Toolchain

```sh
rustup install stable
rustup install nightly-2025-04-01     # what aya-build invokes
rustup component add rust-src --toolchain nightly-2025-04-01
cargo install bpf-linker --locked
```

The pinned nightly is in `crates/moatd-ebpf/rust-toolchain.toml`. The
workspace itself uses stable; only the eBPF crate needs nightly.

## Build

```sh
cargo build              # debug
cargo build --release    # release
```

`cargo build` at the workspace root only builds the userspace crates by
default (`default-members`). The eBPF crate is built via the userspace's
`build.rs` (`aya-build`).

`cargo check --workspace` will fail because it tries to typecheck the eBPF
crate for the host target, which doesn't make sense. Use
`cargo check -p moatd-common -p moatd` instead.

## Tests

```sh
cargo test -p moatd -p moatd-common    # unit tests (15)
sudo make integration-test             # netns scenarios (8) — see Testing
```

## Lint

```sh
cargo clippy -p moatd-common --features user -p moatd -- -D warnings
```

`cargo clippy --workspace` will fail for the same reason as
`cargo check --workspace` (eBPF crate compiled for the wrong target). Use
the per-crate form.

## Adding a new rule field

Touching the wire format is the most invasive change. The path:

1. **`moatd-common`** — add the field to `UserRule` (serde) and / or `Rule`
   (BPF). If you change `Rule`, also update the `_pad` byte counts so
   `bytemuck::Pod` keeps compiling. The derive checks for implicit padding
   at compile time.
2. **`moatd/src/wire.rs`** — handle the new field in `build_wire_rule`.
3. **`moatd/src/parser.rs`** — accept the new grammar token.
4. **`moatd-ebpf/src/main.rs`** — match against the new field in
   `walk_rules`.
5. **Tests** — add at least a parser test and a wire-conversion test.

## Adding a new control command

1. Add a `Request` and (if needed) `Response` variant in
   `moatd-common/src/lib.rs` under `pub mod control`.
2. Implement the dispatch arm in `moatd/src/bin/moatd.rs::dispatch`.
3. Add a `clap` subcommand in `moatd/src/bin/moat.rs`.
4. Add an integration scenario under `tests/integration/scenarios/` if the
   command has observable on-wire effects.

## CI

`.github/workflows/ci.yml` runs two jobs on `ubuntu-24.04`:

- `unit`: `cargo build` + `cargo test`.
- `integration`: full netns suite via `sudo tests/integration/run.sh`.

Both jobs share a cargo cache keyed by `Cargo.lock`. First run on a fresh
runner takes ~3 minutes (mostly bpf-linker install); cached runs finish in
~45 s.
