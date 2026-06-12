# Warpgate on FreeBSD

This document covers building, installing, and running Warpgate on FreeBSD.
Tested on **FreeBSD 15.0-RELEASE**.

---

## Prerequisites

Install the required packages:

```sh
pkg install openjdk17 node20 npm-node20 rustup-init
```

### Why OpenJDK?

Although Warpgate is primarily a Rust application, its web-based admin interface
(`warpgate-web`) is built with Svelte and uses OpenAPI to keep the Rust backend
and TypeScript frontend in sync. During the frontend build, `openapi-generator-cli`
— a Java-based tool — generates the TypeScript API client from the OpenAPI spec.

OpenJDK 17 is required specifically because modern versions of `openapi-generator-cli`
dropped support for Java 8/11. Using an older JDK will produce
`Unsupported Class Version` errors during the frontend build.

### Why Rust Nightly?

Warpgate uses unstable Rust features that are not yet available on the stable
toolchain. Nightly is required to build the project.

---

## Build

> **Important:** The frontend must be built before `cargo build`. The Rust binary
> embeds the compiled frontend assets at compile time. Building in the wrong order
> will produce a working SSH/database gateway but a broken or stale web UI.

### 1. Set up Rust nightly

```sh
rustup-init
rustup toolchain install nightly
rustup default nightly
```

### 2. Build the frontend

```sh
cd warpgate-web
npm install
npm run build
cd ..
```

### 3. Build the backend

```sh
cargo build --release
```

---

## Install

The simplest method using the provided `Makefile.freebsd`:

```sh
make -f Makefile.freebsd install
```

This will:
- Copy the binary to `/usr/local/bin/warpgate`
- Install the rc.d script to `/usr/local/etc/rc.d/warpgate`
- Create the data directory at `/usr/local/var/warpgate`

### Manual install

```sh
install -m 755 target/release/warpgate /usr/local/bin/warpgate
install -m 755 rc.d/warpgate /usr/local/etc/rc.d/warpgate
install -d -m 755 /usr/local/var/warpgate
```

---

## Configuration

Run the interactive setup to generate `/usr/local/etc/warpgate.yaml`:

```sh
warpgate setup
```

---

## rc.d Service

Enable and start Warpgate as a system service:

```sh
# /etc/rc.conf
warpgate_enable="YES"
```

Optional overrides (shown with defaults):

```sh
warpgate_config="/usr/local/etc/warpgate.yaml"
warpgate_logfile="/var/log/warpgate.log"
```

Service management:

```sh
service warpgate start
service warpgate stop
service warpgate restart
service warpgate status
```

### rc.d Implementation Notes

The rc.d script uses `&` and `echo $!` to background the process and write a
proper pidfile rather than wrapping with `daemon(8)`. This is intentional:
`daemon(8)` on FreeBSD 15 writes pidfiles without a trailing newline, which
causes `rc.subr`'s `read` builtin to hang, breaking `service status` and
`service stop`. The `$!` approach writes a newline-terminated pidfile naturally.

`procname` is set to the full binary path (`/usr/local/bin/warpgate`) rather
than the short name because FreeBSD's `ps -o command=` returns the full path,
and `rc.subr` matches against this value for process identification.

The data directory `/usr/local/var/warpgate` is created automatically at service
start if it does not exist, so the service is resilient to missing directories
regardless of how it was installed.

---

## Repository Structure Notes

The repository contains two directories that may appear frontend-related:

- `warpgate-web` — the Svelte frontend, contains `package.json` and is what
  you build with `npm`
- `warpgate-admin` — a Rust crate, not the frontend despite the name

---

## Platform-Specific Code Changes

One FreeBSD-specific change was required in `warpgate/src/commands/setup.rs`
to set the correct default data directory:

```rust
#[cfg(target_os = "freebsd")]
let default_data_path = "/usr/local/var/warpgate".to_string();
```

This follows the FreeBSD Filesystem Hierarchy standard where third-party
software data lives under `/usr/local/var/` rather than `/var/`.