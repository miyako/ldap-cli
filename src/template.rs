//! Placeholder templates with context-aware escaping.
//!
//! `{name}` is replaced by the value of `--arg name=VALUE`, escaped for the context the
//! template is used in (filter → RFC 4515, DN → RFC 4514). Text typed literally in the
//! template keeps its meaning, so `(cn={q}*)` is a safe prefix search. `{{` and `}}`
//! produce literal braces.

use crate::error::{Error, Result};
use crate::escape;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub enum Context {
    Filter,
    Dn,
}

#[derive(Default, Debug)]
pub struct Args {
    values: BTreeMap<String, String>,
    used: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl Args {
    pub fn parse(pairs: &[String], file_pairs: &[String]) -> Result<Self> {
        let mut values = BTreeMap::new();
        for p in pairs {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| Error::usage(format!("--arg '{p}' must be name=value")))?;
            insert(&mut values, k, v.to_string())?;
        }
        for p in file_pairs {
            let (k, path) = p
                .split_once('=')
                .ok_or_else(|| Error::usage(format!("--arg-file '{p}' must be name=path")))?;
            let mut v = std::fs::read_to_string(path)?;
            if v.ends_with('\n') {
                v.pop();
                if v.ends_with('\r') {
                    v.pop();
                }
            }
            insert(&mut values, k, v)?;
        }
        Ok(Args {
            values,
            used: Default::default(),
        })
    }

    pub fn expand(&self, template: &str, ctx: Context) -> Result<String> {
        let mut out = String::with_capacity(template.len());
        let mut it = template.char_indices().peekable();
        while let Some((pos, c)) = it.next() {
            match c {
                '{' if it.peek().map(|x| x.1) == Some('{') => {
                    it.next();
                    out.push('{');
                }
                '}' if it.peek().map(|x| x.1) == Some('}') => {
                    it.next();
                    out.push('}');
                }
                '{' => {
                    let rest = &template[pos + 1..];
                    let end = rest.find('}').ok_or_else(|| {
                        Error::usage(format!("unclosed '{{' in template '{template}'"))
                    })?;
                    let name = &rest[..end];
                    if !valid_name(name) {
                        return Err(Error::usage(format!(
                            "invalid placeholder '{{{name}}}' (use letters, digits, '_'; write '{{{{' for a literal brace)"
                        )));
                    }
                    let v = self.values.get(name).ok_or_else(|| {
                        Error::usage(format!("placeholder '{{{name}}}' has no --arg {name}=…"))
                    })?;
                    self.used.borrow_mut().insert(name.to_string());
                    out.push_str(&match ctx {
                        Context::Filter => escape::filter_value(v),
                        Context::Dn => escape::dn_value(v),
                    });
                    for _ in 0..=name.chars().count() {
                        it.next();
                    }
                }
                '}' => {
                    return Err(Error::usage(format!(
                        "unmatched '}}' in template '{template}' (write '}}}}')"
                    )));
                }
                _ => out.push(c),
            }
        }
        Ok(out)
    }

    /// Arguments that were given but never referenced, which usually indicates a typo.
    pub fn unused(&self) -> Vec<String> {
        let used = self.used.borrow();
        self.values
            .keys()
            .filter(|k| !used.contains(*k))
            .cloned()
            .collect()
    }
}

fn insert(map: &mut BTreeMap<String, String>, k: &str, v: String) -> Result<()> {
    if !valid_name(k) {
        return Err(Error::usage(format!("invalid argument name '{k}'")));
    }
    if map.insert(k.to_string(), v).is_some() {
        return Err(Error::usage(format!("argument '{k}' given more than once")));
    }
    Ok(())
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(p: &[&str]) -> Args {
        Args::parse(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &[]).unwrap()
    }

    #[test]
    fn filter_context_escapes_value_not_template() {
        let a = args(&["q=*)(uid=*"]);
        assert_eq!(
            a.expand("(cn={q}*)", Context::Filter).unwrap(),
            "(cn=\\2a\\29\\28uid=\\2a*)"
        );
    }

    #[test]
    fn dn_context() {
        let a = args(&["cn=Smith, John", "ou=#x"]);
        assert_eq!(
            a.expand("CN={cn},OU={ou},DC=corp", Context::Dn).unwrap(),
            "CN=Smith\\, John,OU=\\#x,DC=corp"
        );
    }

    #[test]
    fn braces_and_errors() {
        let a = args(&["x=1"]);
        assert_eq!(
            a.expand("{{literal}} {x}", Context::Filter).unwrap(),
            "{literal} 1"
        );
        assert!(a.expand("{missing}", Context::Filter).is_err());
        assert!(a.expand("{x", Context::Filter).is_err());
        assert!(a.expand("x}", Context::Filter).is_err());
        assert!(a.expand("{a b}", Context::Filter).is_err());
        let b = args(&["used=1", "typo=2"]);
        b.expand("{used}", Context::Filter).unwrap();
        assert_eq!(b.unused(), vec!["typo".to_string()]);
    }

    #[test]
    fn unicode_values() {
        let a = args(&["n=Zoë (Ω)"]);
        assert_eq!(
            a.expand("(cn={n})", Context::Filter).unwrap(),
            "(cn=Zoë \\28Ω\\29)"
        );
    }

    #[test]
    fn duplicate_arg_rejected() {
        assert!(Args::parse(&["a=1".into(), "a=2".into()], &[]).is_err());
        assert!(Args::parse(&["noequals".into()], &[]).is_err());
    }
}
