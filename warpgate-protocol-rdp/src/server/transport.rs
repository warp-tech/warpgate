//! The private socketpair transport between Warpgate and the serve helper.
//!
//! Warpgate and the helper are wired together by an unnamed `socketpair` rather than a
//! loopback port, so no other local process can connect to or race the RDP byte stream. This
//! module contains the crate's only `unsafe`: a `pre_exec` `dup2` that hands the helper its
//! end of the pair as a fixed inherited fd, kept behind a small safe function.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;

use anyhow::{Context, Result};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use super::HELPER_STREAM_FD;

/// Create the transport socketpair, spawn `command` with the helper's end installed as fd
/// [`HELPER_STREAM_FD`], and return Warpgate's (async) end plus the child. `command` must be
/// fully configured already (subcommand, stdio, `kill_on_drop`).
pub(super) fn spawn_with_transport(command: &mut Command) -> Result<(UnixStream, Child)> {
    let (warpgate_end, helper_end) =
        StdUnixStream::pair().context("creating the RDP serve helper socketpair")?;
    warpgate_end
        .set_nonblocking(true)
        .context("making the RDP transport non-blocking")?;
    let loopback = UnixStream::from_std(warpgate_end).context("wrapping the RDP transport")?;
    let helper_fd = helper_end.as_raw_fd();

    // Hand the helper its end of the socketpair as fd HELPER_STREAM_FD. `dup2` runs in the
    // forked child (pre-exec) and installs a fresh, non-CLOEXEC fd *in that child only*, while
    // `helper_end` keeps CLOEXEC in the parent — so concurrent per-connection spawns can't
    // inherit each other's transport.
    //
    // Safety: the pre-exec closure only calls async-signal-safe `dup2`; `helper_fd` stays
    // valid because `helper_end` is held until after `spawn` returns (dropped just below).
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(helper_fd, HELPER_STREAM_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().context("spawning RDP serve helper")?;
    // The child now holds its own copy of the transport; drop ours so the socket fully closes
    // (and the relay sees EOF) once the helper exits.
    drop(helper_end);
    Ok((loopback, child))
}
