#![allow(dead_code)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn can_skip_line(line: &str) -> bool {
    if let Some(first_char) = line.chars().next() {
        match first_char {
            '#' => true, // comment line
            ';' => true, // comment line
            _ => false,
        }
    } else {
        true // empty line
    }
}

fn is_section_line(line: &str) -> bool {
    if line.trim().is_empty() {
        return false;
    }

    if line.starts_with('[') && line.ends_with(']') {
        return true;
    }

    false
}

fn get_section_name(line: &str) -> Option<String> {
    if !line.trim().is_empty() && line.starts_with('[') && line.ends_with(']') {
        Some(line[1..line.len() - 1].to_string())
    } else {
        None
    }
}

fn try_read_line(reader: &mut impl BufRead, line: &mut String) -> bool {
    line.clear();
    if let Ok(size) = reader.read_line(line) {
        line.truncate(line.trim_end().len());
        size != 0
    } else {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Krb5Conf {
    pub values: Vec<(String, String)>,
    path: Vec<String>,
}

impl Krb5Conf {
    fn new() -> Self {
        Self {
            values: Vec::new(),
            path: Vec::new(),
        }
    }

    pub(crate) fn new_from_file(filename: &Path) -> Option<Self> {
        let file = File::open(filename).ok()?;
        let mut reader = BufReader::new(file);
        let mut config = Krb5Conf::new();
        config.parse_from_reader(&mut reader);
        Some(config)
    }

    pub(crate) fn new_from_data(data: &str) -> Option<Self> {
        let mut reader = BufReader::new(data.as_bytes());
        let mut config = Krb5Conf::new();
        config.parse_from_reader(&mut reader);
        Some(config)
    }

    pub(crate) fn get_value(&self, path: Vec<&str>) -> Option<String> {
        let path = path.join("|");
        for (key, val) in self.values.iter() {
            if key.eq_ignore_ascii_case(&path) {
                return Some(val.clone());
            }
        }
        None
    }

    pub(crate) fn get_values_in_section(&self, path: &[&str]) -> Option<Vec<(&str, &str)>> {
        let mut values = Vec::new();

        let path = path.join("|").to_ascii_lowercase();
        for (key, val) in self.values.iter() {
            if key.to_ascii_lowercase().contains(&path) {
                values.push((&key[path.len() + 1..], val.as_str()));
            }
        }

        if values.is_empty() { None } else { Some(values) }
    }

    fn enter_section(&mut self, name: &str) {
        self.path = vec![name.to_owned()];
    }

    fn enter_group(&mut self, name: &str) {
        self.path.truncate(1);
        self.path.push(name.to_owned());
    }

    fn current_path(&mut self, name: Option<String>) -> String {
        let mut current_path = self.path.clone();
        if let Some(name) = name {
            current_path.push(name);
        }
        current_path.join("|")
    }

    fn parse_from_reader(&mut self, reader: &mut impl BufRead) {
        let mut line = String::new();
        while try_read_line(reader, &mut line) {
            if can_skip_line(&line) {
                continue;
            }

            while is_section_line(&line) {
                self.read_section(reader, &mut line);
            }
        }
    }

    fn add_value(&mut self, key: &str, val: &str) {
        let path = self.current_path(Some(key.to_string()));
        self.values.push((path, val.to_owned()));
    }

    fn read_values(&mut self, reader: &mut impl BufRead, line: &mut String) {
        if let Some((lhs, _)) = line.split_once('=') {
            self.enter_group(lhs.trim());

            while try_read_line(reader, line) {
                if can_skip_line(line) {
                    continue;
                }

                if line.ends_with('}') {
                    break;
                }

                self.read_value(reader, line);
            }
        }
    }

    fn read_value(&mut self, reader: &mut impl BufRead, line: &mut String) {
        if line.contains('{') {
            self.read_values(reader, line);
        } else if let Some(section_name) = get_section_name(line) {
            self.enter_section(section_name.as_str());
        } else if let Some((lhs, rhs)) = line.split_once('=') {
            self.add_value(lhs.trim(), rhs.trim());
        }
    }

    fn read_section(&mut self, reader: &mut impl BufRead, line: &mut String) {
        let name = get_section_name(line).unwrap();
        self.enter_section(&name);

        while try_read_line(reader, line) {
            if can_skip_line(line) {
                continue;
            }

            if line.starts_with('[') {
                break;
            }

            self.read_value(reader, line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Krb5Conf;
    #[test]
    fn test_parse_krb5_conf() {
        let krb5_conf_data = "
[libdefaults]
	default_realm = AD.IT-HELP.NINJA
	udp_preference_limit = 1
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	fcc-mit-ticketflags = true

[realms]
	AD.IT-HELP.NINJA = {
		kdc = IT-HELP-DC.ad.it-help.ninja:88
		admin_server = IT-HELP-DC.ad.it-help.ninja:88
		default_domain = ad.it-help.ninja
	}
";
        let krb5_conf = Krb5Conf::new_from_data(krb5_conf_data).unwrap();

        assert_eq!(
            krb5_conf.get_value(vec!["libdefaults", "default_realm"]),
            Some("AD.IT-HELP.NINJA".to_string())
        );
        assert_eq!(
            krb5_conf.get_value(vec!["realms", "ad.it-help.ninja", "kdc"]),
            Some("IT-HELP-DC.ad.it-help.ninja:88".to_string())
        );
        assert_eq!(
            krb5_conf.get_value(vec!["realms", "ad.it-help.ninja", "admin_server"]),
            Some("IT-HELP-DC.ad.it-help.ninja:88".to_string())
        );
        assert_eq!(
            krb5_conf.get_value(vec!["realms", "ad.it-help.ninja", "default_domain"]),
            Some("ad.it-help.ninja".to_string())
        );
    }
}
