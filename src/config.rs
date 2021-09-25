
use std::fs::File;
use std::str::FromStr;
use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead};
use std::path::Path;
use ipnetwork::{Ipv4Network, IpNetworkError};
use std::net::IpAddr;
use fancy_regex::Regex;
use std::time::Duration;
use byte_unit::{Byte, ByteError};
use parse_duration;
use trust_dns_resolver::{Resolver, error::ResolveError, config::*};


/// A type that can be converted into a int quota.
pub trait ToQuota {
    /// Returns the data this type represents.
    fn to_quota(&self) -> u64;
}


pub mod accnt {
    use super::*;

    pub struct Address { pub value: Vec<Ipv4Network> }

    impl FromStr for Address {
        type Err = ResolveError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut ip_addrs = Address { value: Vec::new() };

            // It is init stage, thus resolution is synchronous
            let resolver = Resolver::new(
                ResolverConfig::default(),
                ResolverOpts::default()).unwrap();
            
            if !s.is_empty() {
                let response = resolver.lookup_ip(s).unwrap();

                for address in response.iter() {
                    // We're working with IPv4 only
                    match address {
                        IpAddr::V4(ipv4) => { 
                            ip_addrs.value.push(Ipv4Network::new(ipv4, 32).unwrap());
                        }
                        _ => continue,
                    }
                }
            }
            
            Ok(ip_addrs)
        }
    }

    pub struct Accounting<T: ToQuota> {
        // Traffic id
        pub addr: Address,
        // Quota size
        pub quota: T,
    }

    pub enum QuotaType {
        Time(Accounting<Duration>),
        Data(Accounting<Byte>),
    }

    // impl Address {
    //     fn new() -> Self {
    //         (Vec<Ipv4Network>::new())
    //     }
    // }

    // impl<T: ToQuota> Accounting<T> {
    //     fn new() -> Accounting<T> {
    //         addr: Address::new(),

    //     }
    // }    

    // pub enum Quota<T, D> {
    //     Data(T),
    //     Time(D)
    // }

    // pub struct Accounting {
    //     // Traffic id
    //     pub addr: Address,
    //     // Quota size
    //     pub quota: Quota,
    // }


    #[derive(Debug)]
    pub enum ParseAccntError {
        // Empty input string
        Empty,
        // Incorrect number of fields
        BadLen,
        // Commented entry
        InnactiveEntry,
        // Wrapped error from parse::<usize>()
        ParseDataQuota(ByteError),
        // Wrapped error from trust_dns_resolver::error
        DNSError(ResolveError),
        // Wrapped error from parse::<usize>()
        ParseTimeQuota(parse_duration::parse::Error),
        // Wrapped error from Ip Network
        ParseIp(IpNetworkError),

        InvalidHostFormat,
        InvalidQuotaFormat,
        // Unhandled
        UnknownError
    }

    impl From<ResolveError> for ParseAccntError {
        fn from(e: ResolveError) -> Self {
            ParseAccntError::DNSError(e)
        }
    }

    impl From<IpNetworkError> for ParseAccntError {
        fn from(e: IpNetworkError) -> Self {
            ParseAccntError::ParseIp(e)
        }
    }

    impl From<parse_duration::parse::Error> for ParseAccntError {
        fn from(e: parse_duration::parse::Error) -> Self {
            ParseAccntError::ParseTimeQuota(e)
        }
    }

    impl From<byte_unit::ByteError> for ParseAccntError {
        fn from(e: byte_unit::ByteError) -> Self {
            ParseAccntError::ParseDataQuota(e)
        }
    }

    impl std::error::Error for ParseAccntError {}

    impl Display for ParseAccntError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use ParseAccntError::*;

            match self {
                Empty => write!(f, "empty line entry"),
                BadLen => write!(f, "incorrect entry format"),
                ParseDataQuota(e) => write!(f, "error parsing data quota: {}", e),
                ParseTimeQuota(e) => write!(f, "error parsing time quota: {}", e),
                DNSError(e) => write!(f, "error in dns resolution: {}", e),
                ParseIp(e) => write!(f, "error parsing ip addr: {}", e),
                _ => write!(f, "unknown error!"),
            }
        }
    }

    impl FromStr for QuotaType {
        type Err = ParseAccntError;

        // TODO write test for this one
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            // "80.249.99.148/32 11mb"
            // "94.142.241.111/32 2m"
            // "# <any info>"
            // "youtube.com 20kb"
            // kb, mb, gb OR s, m, h

            let reg_cidr = Regex::new(
                concat!(
                    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)",
                    r"{3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                    r"([\/][0-3][0-2]?|[\/][1-2][0-9]|[\/][0-9])?$"
                )
            ).unwrap();
        
            let reg_domain = Regex::new(
                concat!(
                    r"^(((?!-))(xn--|_{1,1})?[a-z0-9-]",
                    r"{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9]",
                    r"[a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$",
                )
            ).unwrap();
        
            let reg_data_quota = Regex::new(r"^[0-9]+(kb|mb|gb|kib|mib|gib)$").unwrap();
        
            let reg_time_quota = Regex::new(r"^[0-9]+(s|m|h)$").unwrap();

            match s.len() {
                0 => return Err(ParseAccntError::Empty),
                _ => {
                    if s.chars().next() == Some('#') {
                        return Err(ParseAccntError::InnactiveEntry);
                    }

                    let v: Vec<_> = s.split_whitespace().collect();

                    let (dest_str, quota_str) = match &v[..] {
                        [dest_str, quota_str] => (dest_str.to_owned(), quota_str),
                                    _ => return Err(ParseAccntError::BadLen)
                    };

                    let mut addr = Address { value: Vec::new() };
                    
                    // TODO this one is crippled
                    if reg_cidr.is_match(dest_str).unwrap() {
                        addr.value.push(dest_str.parse::<Ipv4Network>()?);
                    } else if reg_domain.is_match(dest_str).unwrap() {
                        addr = dest_str.parse::<Address>()?;
                    } else {
                        return Err(ParseAccntError::InvalidHostFormat);
                    }

                    if reg_time_quota.is_match(quota_str).unwrap() {
                        let quota = parse_duration::parse(quota_str)?;
                        return Ok(QuotaType::Time( Accounting {addr, quota } ));
                    } else if reg_data_quota.is_match(quota_str).unwrap() {
                        let quota = Byte::from_str(quota_str)?;
                        return Ok(QuotaType::Data( Accounting {addr, quota } ));
                    }

                    return Err(ParseAccntError::InvalidQuotaFormat);
                }
            }
        }
    }
}

use accnt::QuotaType;
use accnt::Accounting as Acc;
use accnt::ParseAccntError as AccErr;


pub struct Config {
    pub data: Vec<Acc<Byte>>,
    pub time: Vec<Acc<Duration>>,
}

#[derive(Debug)]
pub enum ParseConfigError {
    // File not found or whateva ...
    FileError,
    // Parse line error
    EntryError(AccErr,u32),
    // Other error
    UnknownError,
}

impl std::error::Error for ParseConfigError {}

impl Display for ParseConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ParseConfigError::*;

        match self {
            FileError => write!(f, "empty line entry"),
            EntryError(e,i) => write!(f, "error parsing line {0}: {1}", i, e),
            _ => write!(f, "unknown error!"),
        }
    }
}

// impl From<AccErr> for ParseConfigError {
//     fn from(e: AccErr, i: u32) -> Self {
//         ParseConfigError::EntryError(e, i)
//     }
// }


impl Config {
    // TODO do we need this?
    fn new() -> Config {
        Config { 
            data: Vec::new(),
            time: Vec::new(),
        }
    }

    // TODO needs to return some Result as well
    pub fn new_from_file(filepath: &str) -> Result<Config, ParseConfigError> {
        let mut conf = Config::new();

        if let Ok(lines) = Self::read_file(Path::new(filepath)) {
            for (i, line) in lines.enumerate() {
                if let Ok(line) = line {
                    match line.as_str().parse::<QuotaType>() {
                        Ok(entry) => {
                            match entry {
                                QuotaType::Data(a) => conf.data.push(a),
                                QuotaType::Time(a) => conf.time.push(a),
                            }
                        }
                        Err(AccErr::InnactiveEntry) => continue,
                        Err(e) => return Err(ParseConfigError::EntryError(e, i as u32))
                    };
                }
            }
        }

        Ok(conf)
    }

    pub fn read_file<P>(filepath: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path> {
        let file = File::open(filepath)?;
        Ok(io::BufReader::new(file).lines())
    }
}

impl ToQuota for Duration {
    fn to_quota(&self) -> u64 {
        self.as_secs() as u64
    }
}

impl ToQuota for Byte {
    fn to_quota(&self) -> u64 {
        self.get_bytes() as u64
    }
}

#[test]
fn regex_test() {
    let reg_cidr = Regex::new(
        concat!(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)",
            r"{3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            r"([\/][0-3][0-2]?|[\/][1-2][0-9]|[\/][0-9])?$"
        )
    ).unwrap();

    let reg_domain = Regex::new(
        concat!(
            r"^(((?!-))(xn--|_{1,1})?[a-z0-9-]",
            r"{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9]",
            r"[a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$",
        )
    ).unwrap();

    let reg_data_quota = Regex::new(r"^[0-9]+(kb|mb|gb)$").unwrap();

    let reg_time_quota = Regex::new(r"^[0-9]+(s|m|h)$").unwrap();


    assert!(reg_cidr.is_match("192.168.1.1/30").unwrap());
    assert!(reg_cidr.is_match("192.168.1.1").unwrap());
    assert!(reg_cidr.is_match("1.2.3.1/8").unwrap());
    assert!(!reg_cidr.is_match("1.2.3.1/33").unwrap());

    assert!(reg_domain.is_match("google.com").unwrap());
    assert!(reg_domain.is_match("bounty.c").unwrap());
    assert!(!reg_domain.is_match("live.lt.").unwrap());

    assert!(reg_data_quota.is_match("11mb").unwrap());
    assert!(!reg_data_quota.is_match("11m").unwrap());
    assert!(!reg_data_quota.is_match("5215fgf").unwrap());
    
    assert!(!reg_time_quota.is_match("11mb").unwrap());
    assert!(reg_time_quota.is_match("11m").unwrap());
    assert!(!reg_time_quota.is_match("5215fgf").unwrap());
}
