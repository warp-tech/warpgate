pub(super) fn is_rsync_transfer(command: &str) -> bool {
    // Only direct server invocations: keep recording compound commands and
    // shell expansions, which could run unrelated commands as well.
    if command.contains([';', '&', '|', '<', '>', '`', '$', '\n', '\r']) {
        return false;
    }

    let mut args = command.split_ascii_whitespace();
    args.next().and_then(|program| program.rsplit('/').next()) == Some("rsync")
        && args.next() == Some("--server")
}

#[cfg(test)]
mod tests {
    use super::is_rsync_transfer;

    #[test]
    fn recognizes_uploads_and_downloads_without_exempting_other_commands() {
        for command in [
            "rsync --server -logDtpre.iLsfxCIvu . /tmp/upload",
            "rsync --server --sender -logDtpre.iLsfxCIvu . /tmp/download",
            "/usr/bin/rsync --server --sender -logDtpre.iLsfxCIvu . /tmp/download",
            "\trsync\t--server -r . 'directory with spaces'",
        ] {
            assert!(is_rsync_transfer(command), "{command}");
        }

        for command in [
            "",
            "rsync --version",
            "rsync --serverless",
            "rsync-other --server . /tmp/upload",
            "echo rsync --server . /tmp/upload",
            "sudo rsync --server . /tmp/upload",
            "rsync --server . /tmp/upload; echo other-command",
            "rsync --server . /tmp/upload && echo other-command",
            "rsync --server . /tmp/upload | other-command",
            "rsync --server . /tmp/upload > output",
            "rsync --server . /tmp/upload\necho other-command",
            "rsync --server . $(other-command)",
            "rsync --server . `other-command`",
        ] {
            assert!(!is_rsync_transfer(command), "{command}");
        }
    }
}
