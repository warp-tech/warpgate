//! SCP Protocol Parser
//!
//! Parses SCP commands from exec requests and SCP protocol messages.

use super::types::{ScpCommand, ScpMessage};

/// SCP Protocol Parser
#[derive(Default)]
pub struct ScpParser;

impl ScpParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse an exec command to determine if it's SCP
    pub fn parse_command(&self, command: &str) -> ScpCommand {
        let parts: Vec<&str> = command.split_whitespace().collect();

        if parts.is_empty() {
            return ScpCommand::NotScp;
        }

        // Check if it's scp command
        let is_scp = parts[0] == "scp" || parts[0].ends_with("/scp");
        if !is_scp {
            return ScpCommand::NotScp;
        }

        let mut is_upload = false;
        let mut is_download = false;
        let mut recursive = false;
        let mut path = String::new();

        for part in &parts[1..] {
            match *part {
                "-t" => is_upload = true,
                "-f" => is_download = true,
                "-r" => recursive = true,
                _ if !part.starts_with('-') => {
                    path = part.to_string();
                }
                _ => {}
            }
        }

        if is_upload {
            ScpCommand::Upload { path, recursive }
        } else if is_download {
            ScpCommand::Download { path, recursive }
        } else {
            ScpCommand::NotScp
        }
    }

    /// Parse SCP protocol message from data stream
    pub fn parse_message(&self, data: &[u8]) -> Option<ScpMessage> {
        if data.is_empty() {
            return None;
        }

        match data[0] {
            0 => Some(ScpMessage::Ok),
            1 => {
                let msg = String::from_utf8_lossy(&data[1..]).trim().to_string();
                Some(ScpMessage::Warning(msg))
            }
            2 => {
                let msg = String::from_utf8_lossy(&data[1..]).trim().to_string();
                Some(ScpMessage::Error(msg))
            }
            b'C' => self.parse_file_header(data),
            b'D' => self.parse_dir_header(data),
            b'E' => Some(ScpMessage::EndDir),
            _ => Some(ScpMessage::Data(data.to_vec())),
        }
    }

    fn parse_file_header(&self, data: &[u8]) -> Option<ScpMessage> {
        // Format: C<mode> <size> <filename>\n
        let line = String::from_utf8_lossy(data);
        let line = line.trim();

        if !line.starts_with('C') {
            return None;
        }

        let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
        if parts.len() != 3 {
            return None;
        }

        let mode = u32::from_str_radix(parts[0], 8).ok()?;
        let size = parts[1].parse().ok()?;
        let filename = parts[2].to_string();

        Some(ScpMessage::FileHeader {
            mode,
            size,
            filename,
        })
    }

    fn parse_dir_header(&self, data: &[u8]) -> Option<ScpMessage> {
        // Format: D<mode> 0 <dirname>\n
        let line = String::from_utf8_lossy(data);
        let line = line.trim();

        if !line.starts_with('D') {
            return None;
        }

        let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
        if parts.len() != 3 {
            return None;
        }

        let mode = u32::from_str_radix(parts[0], 8).ok()?;
        let dirname = parts[2].to_string();

        Some(ScpMessage::DirHeader { mode, dirname })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upload_command() {
        let parser = ScpParser::new();

        let result = parser.parse_command("scp -t /tmp/dest");
        assert_eq!(
            result,
            ScpCommand::Upload {
                path: "/tmp/dest".to_string(),
                recursive: false
            }
        );
    }

    #[test]
    fn test_parse_upload_recursive() {
        let parser = ScpParser::new();

        let result = parser.parse_command("scp -t -r /tmp/dest");
        assert_eq!(
            result,
            ScpCommand::Upload {
                path: "/tmp/dest".to_string(),
                recursive: true
            }
        );
    }

    #[test]
    fn test_parse_download_command() {
        let parser = ScpParser::new();

        let result = parser.parse_command("scp -f /tmp/source");
        assert_eq!(
            result,
            ScpCommand::Download {
                path: "/tmp/source".to_string(),
                recursive: false
            }
        );
    }

    #[test]
    fn test_parse_full_path_scp() {
        let parser = ScpParser::new();

        let result = parser.parse_command("/usr/bin/scp -t /home/user/file.txt");
        assert_eq!(
            result,
            ScpCommand::Upload {
                path: "/home/user/file.txt".to_string(),
                recursive: false
            }
        );
    }

    #[test]
    fn test_parse_not_scp() {
        let parser = ScpParser::new();

        assert_eq!(parser.parse_command("ls -la"), ScpCommand::NotScp);
        assert_eq!(parser.parse_command(""), ScpCommand::NotScp);
        assert_eq!(parser.parse_command("cat /etc/passwd"), ScpCommand::NotScp);
    }

    #[test]
    fn test_parse_file_header() {
        let parser = ScpParser::new();

        let data = b"C0644 1234 test.txt\n";
        let result = parser.parse_message(data);

        if let Some(ScpMessage::FileHeader {
            mode,
            size,
            filename,
        }) = result
        {
            assert_eq!(mode, 0o644);
            assert_eq!(size, 1234);
            assert_eq!(filename, "test.txt");
        } else {
            panic!("Expected FileHeader");
        }
    }

    #[test]
    fn test_parse_dir_header() {
        let parser = ScpParser::new();

        let data = b"D0755 0 mydir\n";
        let result = parser.parse_message(data);

        if let Some(ScpMessage::DirHeader { mode, dirname }) = result {
            assert_eq!(mode, 0o755);
            assert_eq!(dirname, "mydir");
        } else {
            panic!("Expected DirHeader");
        }
    }

    #[test]
    fn test_parse_ok() {
        let parser = ScpParser::new();

        let result = parser.parse_message(&[0]);
        assert!(matches!(result, Some(ScpMessage::Ok)));
    }

    #[test]
    fn test_parse_warning() {
        let parser = ScpParser::new();

        let mut data = vec![1u8];
        data.extend_from_slice(b"warning message");
        let result = parser.parse_message(&data);

        if let Some(ScpMessage::Warning(msg)) = result {
            assert_eq!(msg, "warning message");
        } else {
            panic!("Expected Warning");
        }
    }

    #[test]
    fn test_parse_error() {
        let parser = ScpParser::new();

        let mut data = vec![2u8];
        data.extend_from_slice(b"error message");
        let result = parser.parse_message(&data);

        if let Some(ScpMessage::Error(msg)) = result {
            assert_eq!(msg, "error message");
        } else {
            panic!("Expected Error");
        }
    }

    #[test]
    fn test_parse_end_dir() {
        let parser = ScpParser::new();

        let result = parser.parse_message(b"E\n");
        assert!(matches!(result, Some(ScpMessage::EndDir)));
    }
}
