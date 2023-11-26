//! # hosts_to
//! A library for parsing hosts file entries.
//! This library provides a way to parse hosts file entries into a format that can be used

///////////////////////////////////////////////////////////////////////////////

use thiserror::Error;

use std::net::{AddrParseError, IpAddr};

/// Re-export of trust-dns-proto
#[cfg(feature = "trust-dns-proto")]
pub use ::trust_dns_proto;

/// Error type for parsing hosts file entries.
/// This sturct corresponds to a line in the hosts file.
/// See `HostEntry` for a version that owns its data.
#[derive(Error, Debug, Clone)]
#[error("{0}")]
pub enum ParseHostEntryError {
    #[error("EmptyLine")]
    EmptyLine,
    ParseLineError(String),
    AddrParseError(#[from] AddrParseError),
}

/// A reference to a single line of a hosts file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntryRef<'a> {
    pub ipaddr: IpAddr,
    pub hostnames: Vec<&'a str>,
}

impl HostEntryRef<'_> {
    /// Parses a single line of a hosts file.
    ///
    /// This function will parse a line of text into a `HostEntryRef`.
    /// It ignores any comments (starting with '#') and leading whitespace.
    ///
    /// # Arguments
    ///
    /// * `line` - A string slice representing a single line from a hosts file.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(HostEntryRef))` if the line contains a valid host entry.
    /// Returns `Ok(None)` if the line is empty or only contains a comment.
    /// Returns `Err(ParseHostEntryError)` if the line contains an invalid format.
    pub fn parse_line_str(line: &str) -> Result<Option<HostEntryRef<'_>>, ParseHostEntryError> {
        use ParseHostEntryError::*;
        let s = line.trim_start();
        let s = match s.split_once('#') {
            None => s,
            Some((s, _)) => s,
        };
        let (ipaddr, s) = match s.split_once(char::is_whitespace) {
            None => return Ok(None),
            Some(o) => o,
        };

        let ipaddr = ipaddr.parse()?;
        let hostnames = s.split_ascii_whitespace().collect::<Vec<_>>();
        if hostnames.is_empty() {
            Err(ParseLineError(line.to_string()))
        } else {
            Ok(Some(HostEntryRef { ipaddr, hostnames }))
        }
    }

    /// Parses a string into a vector of `HostEntryRef`.
    ///
    /// This function processes each line of the input string as a hosts file entry,
    /// using `parse_line_str` for each line.
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice representing the contents of a hosts file.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<HostEntryRef>)` containing all parsed host entries.
    /// Returns `Err(ParseHostEntryError)` if any line contains an invalid format.
    pub fn parse_str_to_vec(s: &str) -> Result<Vec<HostEntryRef<'_>>, ParseHostEntryError> {
        let mut result = vec![];
        for line in s.lines() {
            if let Some(r) = HostEntryRef::parse_line_str(line)? {
                result.push(r);
            }
        }
        Ok(result)
    }
}

/// A single entry in a hosts file.
/// This sturct corresponds to a line in the hosts file.
/// This struct owns its data.
/// See `HostEntryRef` for a non-owning version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub ipaddr: IpAddr,
    pub hostnames: Vec<String>,
}

impl std::convert::From<HostEntryRef<'_>> for HostEntry {
    /// Converts `HostEntryRef` into `HostEntry`.
    ///
    /// This conversion takes a `HostEntryRef` and creates a new `HostEntry`
    /// instance with owned data. The IP address is copied, and all hostnames
    /// are converted to owned `String`s.
    ///
    /// # Returns
    ///
    /// Returns a new `HostEntry` instance with data owned by the struct.
    fn from(h: HostEntryRef<'_>) -> Self {
        HostEntry {
            ipaddr: h.ipaddr,
            hostnames: h
                .hostnames
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        }
    }
}

impl std::str::FromStr for HostEntry {
    type Err = ParseHostEntryError;

    /// Parses a string slice into a `HostEntry`.
    ///
    /// Attempts to parse a single line of a hosts file as a `HostEntry`.
    /// This will handle any leading whitespace and ignore comments.
    ///
    /// # Returns
    ///
    /// Returns `Ok(HostEntry)` if the line is successfully parsed.
    /// Returns `Err(ParseHostEntryError)` if the line is invalid or empty.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HostEntryRef::parse_line_str(s)?
            .ok_or(ParseHostEntryError::EmptyLine)?
            .into())
    }
}

impl HostEntry {
    /// Parses a string into a vector of `HostEntry`.
    ///
    /// This function processes each line of the input string as a hosts file entry,
    /// parsing them into `HostEntry` objects.
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice representing the contents of a hosts file.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<HostEntry>)` containing all parsed host entries.
    /// Returns `Err(ParseHostEntryError)` if any line contains an invalid format.
    pub fn parse_str_to_vec(s: &str) -> Result<Vec<Self>, ParseHostEntryError> {
        Ok(HostEntryRef::parse_str_to_vec(s)?
            .into_iter()
            .map(Into::<HostEntry>::into)
            .collect())
    }
}

/// Single ip address and hostname pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub ipaddr: IpAddr,
    pub name: String,
}

/// Iterator over `Record`s in a `HostEntry`.
pub struct RecordIter(IpAddr, std::vec::IntoIter<String>);

impl std::iter::IntoIterator for HostEntry {
    type Item = Record;
    type IntoIter = RecordIter;

    /// Creates an iterator over `Record`s in a `HostEntry`.
    fn into_iter(self) -> Self::IntoIter {
        RecordIter(self.ipaddr, self.hostnames.into_iter())
    }
}

impl std::iter::Iterator for RecordIter {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.1.next().map(|name| Record {
            ipaddr: self.0,
            name,
        })
    }
}

#[cfg(feature = "trust-dns-proto")]
impl std::convert::TryInto<trust_dns_proto::rr::resource::Record> for Record {
    type Error = trust_dns_proto::error::ProtoError;

    fn try_into(self) -> Result<trust_dns_proto::rr::resource::Record, Self::Error> {
        use trust_dns_proto::rr::rdata::a::A;
        use trust_dns_proto::rr::rdata::aaaa::AAAA;
        use trust_dns_proto::rr::record_data::RData;
        use trust_dns_proto::rr::record_type::RecordType;
        let mut r = trust_dns_proto::rr::resource::Record::with(
            self.name.parse()?,
            match &self.ipaddr {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            },
            0,
        );
        r.set_data(Some(match self.ipaddr {
            IpAddr::V4(ip) => RData::A(A(ip)),
            IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
        }));

        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn empty_line() {
        assert_eq!(HostEntryRef::parse_line_str("").unwrap(), None);
        assert_eq!(HostEntryRef::parse_line_str("#").unwrap(), None);
        assert_eq!(HostEntryRef::parse_line_str(" #").unwrap(), None);
    }

    #[test]
    fn ipv4_localhost() {
        assert_eq!(
            HostEntryRef::parse_line_str("127.0.0.1 localhost")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost"],
            }
        );
        assert_eq!(
            HostEntryRef::parse_line_str("127.0.0.1 \tlocalhost")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost"],
            }
        );
        assert_eq!(
            HostEntryRef::parse_line_str("127.0.0.1 localhost.private  localhost ")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost.private", "localhost"],
            }
        );
    }

    #[test]
    fn ipv6_localhost() {
        assert_eq!(
            HostEntryRef::parse_line_str("::1 localhost.private localhost")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
                hostnames: vec!["localhost.private", "localhost"],
            }
        );
    }

    #[test]
    fn sharp_ended() {
        assert_eq!(
            HostEntryRef::parse_line_str("127.0.0.1 localhost#")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost"],
            }
        );
    }

    #[test]
    fn with_comment() {
        assert_eq!(
            HostEntryRef::parse_line_str("127.0.0.1 localhost#test")
                .unwrap()
                .unwrap(),
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost"],
            }
        );
    }

    #[test]
    fn multiple_lines_empty() {
        assert_eq!(HostEntryRef::parse_str_to_vec("").unwrap(), vec![]);
        assert_eq!(HostEntryRef::parse_str_to_vec("#").unwrap(), vec![]);
        assert_eq!(HostEntryRef::parse_str_to_vec("#\n").unwrap(), vec![]);
        assert_eq!(HostEntryRef::parse_str_to_vec("\n\n").unwrap(), vec![]);
    }

    #[test]
    fn mulitple_lines_real() {
        assert_eq!(
            HostEntryRef::parse_str_to_vec("127.0.0.1 localhost #comment\n::1 localhost\n# comment\n\nbeef::cafe\texample.com \t")
                .unwrap(),
                vec![
            HostEntryRef {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["localhost"],
            },
            HostEntryRef {
                ipaddr: Ipv6Addr::new(0,0,0,0,0,0,0,1).into(),
                hostnames: vec!["localhost"],
            },
            HostEntryRef {
                ipaddr: Ipv6Addr::new(0xbeef, 0, 0, 0, 0, 0, 0, 0xcafe).into(),
                hostnames: vec!["example.com"],
            },]
        );
    }

    #[test]
    fn from_str() {
        assert_eq!(
            "127.0.0.1 example.com".parse::<HostEntry>().unwrap(),
            HostEntry {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["example.com".to_string()],
            }
        );
    }

    #[test]
    fn entry_into_iter() {
        assert_eq!(
            HostEntry {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                hostnames: vec!["example.com".to_string()],
            }
            .into_iter()
            .collect::<Vec<_>>(),
            vec![Record {
                ipaddr: Ipv4Addr::new(127, 0, 0, 1).into(),
                name: "example.com".to_string()
            }]
        );
        assert_eq!(
            "127.0.0.1 example.com"
                .parse::<HostEntry>()
                .unwrap()
                .into_iter()
                .map(|e| format!("{} {}", e.ipaddr, e.name))
                .collect::<Vec<_>>(),
            vec!["127.0.0.1 example.com"]
        );
    }

    #[cfg(feature = "trust-dns-proto")]
    #[test]
    fn trust_dns() {
        use trust_dns_proto::rr::resource::Record as TRecord;
        assert_eq!(
            "127.0.0.1 example.com"
                .parse::<HostEntry>()
                .unwrap()
                .into_iter()
                .map(|e| format!("{}", TryInto::<TRecord>::try_into(e).unwrap()))
                .collect::<Vec<String>>(),
            vec!["example.com 0 IN A 127.0.0.1"]
        );
    }
}
