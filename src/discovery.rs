//! Domain controller discovery via DNS SRV records (RFC 2782), with a domain-suffix check
//! because SRV answers are not authenticated. The CLDAP "LDAP ping" for site discovery is
//! deferred; use --site.

use crate::error::{Error, Result};
use crate::model::Target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

pub fn locate(
    domain: &str,
    site: Option<&str>,
    gc: bool,
    port: u16,
    allow_foreign: bool,
) -> Result<Vec<Target>> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let svc = if gc { "_gc._tcp" } else { "_ldap._tcp" };
    let zone = if gc {
        format!("gc._msdcs.{domain}")
    } else {
        format!("dc._msdcs.{domain}")
    };
    let mut names = Vec::new();
    if let Some(s) = site {
        names.push(format!("{svc}.{s}._sites.{zone}"));
    }
    names.push(format!("{svc}.{zone}"));

    let mut hosts: Vec<String> = crate::backend::preferred_dc(&domain, site, gc)
        .into_iter()
        .collect();
    for name in &names {
        let records = crate::backend::query_srv(name)?;
        if !records.is_empty() {
            hosts.extend(order(records).into_iter().map(|r| r.target));
            break;
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut targets = Vec::new();
    for h in hosts {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        if !seen.insert(h.clone()) {
            continue;
        }
        if !allow_foreign && !in_domain(&h, &domain) {
            eprintln!(
                "warning: ignoring SRV target '{h}' outside {domain} (use --allow-foreign-dc to accept)"
            );
            continue;
        }
        // The SRV port is the plain LDAP/GC port; TLS mode decides the port we use.
        targets.push(Target { host: h, port });
    }
    if targets.is_empty() {
        return Err(Error::connect(format!(
            "no domain controllers found for {domain} ({})",
            names.join(", ")
        )));
    }
    Ok(targets)
}

pub fn in_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// RFC 2782 ordering: ascending priority, weighted random within a priority.
pub fn order(mut records: Vec<Srv>) -> Vec<Srv> {
    records.sort_by_key(|r| r.priority);
    let mut out = Vec::with_capacity(records.len());
    let mut i = 0;
    while i < records.len() {
        let p = records[i].priority;
        let mut group: Vec<Srv> = records[i..]
            .iter()
            .take_while(|r| r.priority == p)
            .cloned()
            .collect();
        i += group.len();
        while !group.is_empty() {
            let total: u32 = group.iter().map(|r| r.weight as u32).sum();
            let pick = if total == 0 {
                0
            } else {
                let mut n = random_u32() % (total + 1);
                group
                    .iter()
                    .position(|r| {
                        if n <= r.weight as u32 {
                            true
                        } else {
                            n -= r.weight as u32;
                            false
                        }
                    })
                    .unwrap_or(0)
            };
            out.push(group.remove(pick));
        }
    }
    out
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_check() {
        assert!(in_domain("dc1.corp.example", "corp.example"));
        assert!(!in_domain("evilcorp.example", "corp.example"));
        assert!(!in_domain("dc1.corp.example.evil.com", "corp.example"));
    }

    #[test]
    fn ordering() {
        let r = |p, w, t: &str| Srv {
            priority: p,
            weight: w,
            port: 389,
            target: t.into(),
        };
        let o = order(vec![
            r(10, 0, "c"),
            r(0, 100, "a"),
            r(0, 0, "b"),
            r(5, 1, "x"),
        ]);
        assert_eq!(o.len(), 4);
        assert!(o[0].priority == 0 && o[1].priority == 0);
        assert_eq!(o[2].target, "x");
        assert_eq!(o[3].target, "c");
    }
}
