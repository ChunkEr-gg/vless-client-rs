//! Inline CIDR and domain routing predicates (`PLAN.md` §6).

pub mod domain;
pub mod ip;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use domain::{DomainKind, Names};
pub use ip::IpRanges;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn contains_sorted<T: Ord + Copy>(ranges: &[(T, T)], target: T) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= target);
    idx > 0 && target <= ranges[idx - 1].1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Stun,
    Dtls,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stun => "stun",
            Self::Dtls => "dtls",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Traffic {
    pub network: Network,
    pub protocol: Option<Protocol>,
}

impl Traffic {
    pub const TCP: Self = Self {
        network: Network::Tcp,
        protocol: None,
    };
    pub const UDP: Self = Self {
        network: Network::Udp,
        protocol: None,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Match,
    Miss,
    Unknown { may_resolve: bool },
}

impl Outcome {
    fn any(values: impl Iterator<Item = Self>) -> Self {
        Self::combine(values, false)
    }

    fn all(values: impl Iterator<Item = Self>) -> Self {
        Self::combine(values, true)
    }

    pub fn negate(self) -> Self {
        match self {
            Self::Match => Self::Miss,
            Self::Miss => Self::Match,
            unknown => unknown,
        }
    }

    fn combine(values: impl Iterator<Item = Self>, and: bool) -> Self {
        let mut unknown = None;
        for value in values {
            match value {
                Self::Miss if and => return Self::Miss,
                Self::Match if !and => return Self::Match,
                Self::Unknown { may_resolve } => {
                    unknown = Some(unknown.unwrap_or(false) || may_resolve);
                }
                _ => {}
            }
        }
        unknown.map_or(if and { Self::Match } else { Self::Miss }, |may_resolve| {
            Self::Unknown { may_resolve }
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Dependencies {
    pub hostname: bool,
    pub ip: bool,
    pub network: bool,
    pub protocol: bool,
}

#[derive(Debug)]
pub struct Predicate {
    pub dependencies: Dependencies,
    pub(crate) kind: Kind,
}

#[derive(Debug)]
pub(crate) enum Kind {
    Constant(bool),
    Domains(Names, DomainKind),
    Ips(IpRanges, bool),
    Ports(Box<[(u16, u16)]>),
    Any(Box<[Arc<Predicate>]>),
    All(Box<[Arc<Predicate>]>),
    Not(Arc<Predicate>),
}

impl Predicate {
    pub fn match_all() -> Arc<Self> {
        Self::new(Kind::Constant(true))
    }

    pub fn from_cidrs(cidrs: &[IpNetwork], no_resolve: bool) -> io::Result<Arc<Self>> {
        if cidrs.is_empty() {
            return Ok(Self::new(Kind::Constant(false)));
        }
        let mut ranges = IpRanges::default();
        for cidr in cidrs {
            ranges.add_cidr(&cidr.to_string())?;
        }
        Ok(Self::new(Kind::Ips(ranges.finish(), no_resolve)))
    }

    pub fn from_domain_suffixes(domains: Vec<String>) -> io::Result<Arc<Self>> {
        Self::from_domain_patterns(&domains)
    }

    /// Compiles domain bypass patterns (`*.example.com`, `.example.com`, `example.com`) into a predicate:
    /// - `*.foo` matches subdomains of `foo` (`DomainKind::Subdomains`)
    /// - `.foo` or `foo` matches `foo` and subdomains of `foo` (`DomainKind::Suffix`)
    pub fn from_domain_patterns(patterns: &[String]) -> io::Result<Arc<Self>> {
        let mut subdomains = Vec::new();
        let mut suffixes = Vec::new();
        for pat in patterns {
            let trimmed = pat.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("*.") {
                subdomains.push(rest.to_owned());
            } else if let Some(rest) = trimmed.strip_prefix('.') {
                suffixes.push(rest.to_owned());
            } else {
                suffixes.push(trimmed.to_owned());
            }
        }
        let mut children = Vec::new();
        if !subdomains.is_empty() {
            children.push(Self::new(Kind::Domains(
                Names::new(subdomains)?,
                DomainKind::Subdomains,
            )));
        }
        if !suffixes.is_empty() {
            children.push(Self::new(Kind::Domains(
                Names::new(suffixes)?,
                DomainKind::Suffix,
            )));
        }
        Ok(Self::any(children))
    }

    pub fn any(children: Vec<Arc<Self>>) -> Arc<Self> {
        if children.is_empty() {
            return Self::new(Kind::Constant(false));
        }
        if children.len() == 1 {
            return children.into_iter().next().unwrap();
        }
        Self::new(Kind::Any(children.into()))
    }

    pub fn all(children: Vec<Arc<Self>>) -> Arc<Self> {
        if children.is_empty() {
            return Self::new(Kind::Constant(true));
        }
        if children.len() == 1 {
            return children.into_iter().next().unwrap();
        }
        Self::new(Kind::All(children.into()))
    }

    pub fn ports(ranges: Vec<(u16, u16)>) -> Arc<Self> {
        Self::new(Kind::Ports(ranges.into()))
    }

    pub fn negate(child: Arc<Self>) -> Arc<Self> {
        Self::new(Kind::Not(child))
    }

    pub(crate) fn new(kind: Kind) -> Arc<Self> {
        let dependencies = match &kind {
            Kind::Domains(..) => Dependencies {
                hostname: true,
                ..Dependencies::default()
            },
            Kind::Ips(..) => Dependencies {
                ip: true,
                ..Dependencies::default()
            },
            Kind::Any(ps) | Kind::All(ps) => {
                let mut deps = Dependencies::default();
                for p in ps {
                    deps.hostname |= p.dependencies.hostname;
                    deps.ip |= p.dependencies.ip;
                    deps.network |= p.dependencies.network;
                    deps.protocol |= p.dependencies.protocol;
                }
                deps
            }
            Kind::Not(p) => p.dependencies,
            Kind::Constant(_) | Kind::Ports(_) => Dependencies::default(),
        };
        Arc::new(Self { dependencies, kind })
    }

    #[allow(clippy::only_used_in_recursion)]
    pub fn evaluate(
        &self,
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
        traffic: Traffic,
        no_resolve: bool,
    ) -> Outcome {
        match &self.kind {
            Kind::Constant(true) => Outcome::Match,
            Kind::Constant(false) => Outcome::Miss,
            Kind::Domains(names, kind) => match hostname {
                Some(h) => {
                    let normalized = domain::normalize(h);
                    match normalized {
                        Ok(name) if names.matches(&name, *kind) => Outcome::Match,
                        _ => Outcome::Miss,
                    }
                }
                None => Outcome::Miss,
            },
            Kind::Ips(ranges, rule_no_resolve) => match ip {
                Some(addr) => {
                    if ranges.contains(addr) {
                        Outcome::Match
                    } else {
                        Outcome::Miss
                    }
                }
                None => {
                    if no_resolve || *rule_no_resolve || hostname.is_none() {
                        Outcome::Miss
                    } else {
                        Outcome::Unknown { may_resolve: true }
                    }
                }
            },
            Kind::Ports(ranges) => {
                if ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi) {
                    Outcome::Match
                } else {
                    Outcome::Miss
                }
            }
            Kind::Any(ps) => Outcome::any(
                ps.iter()
                    .map(|p| p.evaluate(hostname, ip, port, traffic, no_resolve)),
            ),
            Kind::All(ps) => Outcome::all(
                ps.iter()
                    .map(|p| p.evaluate(hostname, ip, port, traffic, no_resolve)),
            ),
            Kind::Not(p) => p.evaluate(hostname, ip, port, traffic, no_resolve).negate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_domain_predicates_evaluate_accurately() {
        let cidrs = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];
        let ip_pred = Predicate::from_cidrs(&cidrs, true).unwrap();
        assert_eq!(
            ip_pred.evaluate(
                None,
                Some("10.1.2.3".parse().unwrap()),
                443,
                Traffic::TCP,
                false
            ),
            Outcome::Match
        );
        assert_eq!(
            ip_pred.evaluate(
                None,
                Some("1.1.1.1".parse().unwrap()),
                443,
                Traffic::TCP,
                false
            ),
            Outcome::Miss
        );
        // no_resolve = true means hostname without IP misses instead of requesting DNS
        assert_eq!(
            ip_pred.evaluate(Some("example.com"), None, 443, Traffic::TCP, false),
            Outcome::Miss
        );

        let dom_pred =
            Predicate::from_domain_suffixes(vec![".local".into(), "corp.internal".into()]).unwrap();
        assert_eq!(
            dom_pred.evaluate(Some("printer.local"), None, 80, Traffic::TCP, false),
            Outcome::Match
        );
        assert_eq!(
            dom_pred.evaluate(Some("api.corp.internal"), None, 443, Traffic::TCP, false),
            Outcome::Match
        );
        assert_eq!(
            dom_pred.evaluate(Some("example.com"), None, 443, Traffic::TCP, false),
            Outcome::Miss
        );
    }
}
