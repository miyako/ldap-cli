//! Search result output: LDIF, JSON, JSON Lines and CSV.

use crate::ad;
use crate::error::Result;
use crate::ldif;
use crate::model::Entry;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Ldif,
    Json,
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Binary {
    Base64,
    Hex,
    Decode,
}

pub struct Output {
    format: Format,
    binary: Binary,
    wrap: usize,
    columns: Vec<String>,
    buffered: Vec<Entry>,
    count: usize,
    out: Box<dyn Write>,
}

impl Output {
    pub fn new(format: Format, binary: Binary, wrap: usize, columns: Vec<String>) -> Self {
        Output {
            format,
            binary,
            wrap,
            columns,
            buffered: Vec::new(),
            count: 0,
            out: Box::new(std::io::stdout().lock()),
        }
    }

    pub fn entry(&mut self, e: Entry) -> Result<()> {
        self.count += 1;
        match self.format {
            Format::Ldif => {
                let binary = self.binary;
                let s = ldif::write_entry(&e, self.wrap, |a, v| {
                    if binary == Binary::Decode {
                        ad::decode(a, v)
                    } else {
                        None
                    }
                });
                self.out.write_all(s.as_bytes())?;
            }
            Format::Jsonl => {
                let v = self.to_json(&e);
                writeln!(self.out, "{v}")?;
            }
            Format::Json | Format::Csv => self.buffered.push(e),
        }
        Ok(())
    }

    pub fn reference(&mut self, uris: &[String]) -> Result<()> {
        if self.format == Format::Ldif {
            for u in uris {
                writeln!(self.out, "# search reference: {u}\n")?;
            }
        } else {
            eprintln!("search reference: {}", uris.join(" "));
        }
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn finish(mut self) -> Result<()> {
        match self.format {
            Format::Json => {
                let arr: Vec<Value> = self.buffered.iter().map(|e| self.to_json(e)).collect();
                serde_json::to_writer_pretty(&mut self.out, &arr).map_err(std::io::Error::from)?;
                writeln!(self.out)?;
            }
            Format::Csv => self.write_csv()?,
            _ => {}
        }
        self.out.flush()?;
        Ok(())
    }

    fn render(&self, attr: &str, v: &[u8]) -> Value {
        if self.binary == Binary::Decode {
            if let Some(s) = ad::decode(attr, v) {
                return Value::String(s);
            }
        }
        match std::str::from_utf8(v) {
            Ok(s) if !ad::is_binary_attr(attr) => Value::String(s.to_string()),
            _ => match self.binary {
                Binary::Hex => json!({ "hex": hex(v) }),
                _ => json!({ "base64": B64.encode(v) }),
            },
        }
    }

    fn render_text(&self, attr: &str, v: &[u8]) -> String {
        match self.render(attr, v) {
            Value::String(s) => s,
            Value::Object(o) => o
                .values()
                .next()
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            other => other.to_string(),
        }
    }

    fn to_json(&self, e: &Entry) -> Value {
        let mut attrs = Map::new();
        for (a, vs) in &e.attrs {
            attrs.insert(
                a.clone(),
                Value::Array(vs.iter().map(|v| self.render(a, v)).collect()),
            );
        }
        json!({ "dn": e.dn, "attributes": attrs })
    }

    fn write_csv(&mut self) -> Result<()> {
        let mut cols = self
            .columns
            .iter()
            .filter(|c| !matches!(c.as_str(), "*" | "+" | "1.1"))
            .cloned()
            .collect::<Vec<_>>();
        if cols.is_empty() {
            for e in &self.buffered {
                for (a, _) in &e.attrs {
                    if !cols.iter().any(|c| c.eq_ignore_ascii_case(a)) {
                        cols.push(a.clone());
                    }
                }
            }
        }
        let mut s = String::new();
        s.push_str(&csv_row(
            std::iter::once("dn".to_string()).chain(cols.iter().cloned()),
        ));
        for e in &self.buffered {
            let row = std::iter::once(e.dn.clone()).chain(cols.iter().map(|c| {
                e.get(c)
                    .map(|vs| {
                        vs.iter()
                            .map(|v| self.render_text(c, v))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default()
            }));
            s.push_str(&csv_row(row));
        }
        self.out.write_all(s.as_bytes())?;
        Ok(())
    }
}

fn csv_row(cells: impl Iterator<Item = String>) -> String {
    let mut line = cells
        .map(|c| {
            if c.contains([',', '"', '\n', '\r']) || c.starts_with(' ') || c.ends_with(' ') {
                format!("\"{}\"", c.replace('"', "\"\""))
            } else {
                c
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

pub fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quoting() {
        assert_eq!(
            csv_row(["a".into(), "b,c".into(), "q\"x".into()].into_iter()),
            "a,\"b,c\",\"q\"\"x\"\r\n"
        );
    }

    #[test]
    fn json_binary() {
        let o = Output::new(Format::Json, Binary::Base64, 0, vec![]);
        assert_eq!(o.render("cn", b"x"), json!("x"));
        assert_eq!(
            o.render("objectGUID", &[0u8; 16]),
            json!({"base64": "AAAAAAAAAAAAAAAAAAAAAA=="})
        );
        assert_eq!(o.render("x", &[0xff]), json!({"base64": "/w=="}));
        let d = Output::new(Format::Json, Binary::Decode, 0, vec![]);
        assert_eq!(
            d.render("objectGUID", &[0u8; 16]),
            json!("00000000-0000-0000-0000-000000000000")
        );
    }
}
