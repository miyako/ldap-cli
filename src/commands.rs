//! Command implementations on top of the backend-neutral Session.

use crate::backend::{self, Session};
use crate::ber;
use crate::cli::*;
use crate::config::{self, Profile};
use crate::error::{Error, Result};
use crate::escape;
use crate::filter;
use crate::ldif::{self, Change};
use crate::model::*;
use crate::output::{Binary, Format, Output};
use crate::policy;
use crate::secret::{self, Secret, Source, StdinGuard};
use crate::template::{Args, Context};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::Digest;
use std::io::{IsTerminal, Read};

pub fn run(cli: Cli) -> Result<()> {
    let g = cli.global;
    // Offline commands first: no profile, no connection.
    match cli.command {
        Command::Escape(e) => {
            match e {
                EscapeCmd::Filter { value } => println!("{}", escape::filter_value(&value)),
                EscapeCmd::Dn { value } => println!("{}", escape::dn_value(&value)),
                EscapeCmd::UnescapeDn { value } => println!("{}", escape::dn_unescape(&value)?),
            }
            return Ok(());
        }
        Command::Dn(DnCmd::Parse { dn }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&escape::parse_dn(&dn)?).unwrap()
            );
            return Ok(());
        }
        Command::Dn(DnCmd::Build { template, t }) => {
            let args = Args::parse(&t.arg, &t.arg_file)?;
            let dn = args.expand(&template, Context::Dn)?;
            escape::parse_dn(&dn)?;
            warn_unused(&args);
            println!("{dn}");
            return Ok(());
        }
        _ => {}
    }

    let profile = config::load(g.profile.as_deref())?;
    let mut stdin = StdinGuard::default();
    // Commands that read LDIF or DNs from stdin claim it before credentials do.
    let file_stdin = match &cli.command {
        Command::Add(a) => a.file.as_deref() == Some("-"),
        Command::Modify(m) => m.file.as_deref() == Some("-"),
        Command::Delete(d) => d.file.as_deref() == Some("-"),
        Command::Passwd(p) => p.new_password_stdin,
        _ => false,
    };
    if file_stdin {
        stdin.claim("the command's stdin input")?;
    }
    let mut resolved = policy::resolve(&g, &profile, &mut stdin)?;
    if let Command::Probe(_) = &cli.command {
        resolved.connect.tls.capture_chain = true;
    }
    let ctx = Ctx {
        g: &g,
        profile: &profile,
        opts: &resolved.connect,
    };

    // Read write-command input before connecting so usage errors don't cost a bind.
    match cli.command {
        Command::Search(a) => {
            let mut s = backend::connect(&resolved.connect)?;
            search(&ctx, s.as_mut(), a)
        }
        Command::Add(a) => {
            let changes = add_changes(&a)?;
            let ctrls = parse_controls(&a.t.control)?;
            apply_all(&ctx, changes, &ctrls, a.continue_on_error)
        }
        Command::Modify(a) => {
            let changes = modify_changes(&a)?;
            let ctrls = parse_controls(&a.t.control)?;
            apply_all(&ctx, changes, &ctrls, a.continue_on_error)
        }
        Command::Delete(a) => delete(&ctx, a),
        Command::Modrdn(a) => {
            let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
            let dn = args.expand(&a.dn, Context::Dn)?;
            let new_rdn = args.expand(&a.new_rdn, Context::Dn)?;
            let sup = a
                .new_superior
                .as_deref()
                .map(|s| args.expand(s, Context::Dn))
                .transpose()?;
            warn_unused(&args);
            let ctrls = parse_controls(&a.t.control)?;
            let change = Change::ModRdn {
                dn,
                new_rdn,
                delete_old: !a.keep_old_rdn,
                new_superior: sup,
            };
            apply_all(&ctx, vec![change], &ctrls, false)
        }
        Command::Compare(a) => {
            let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
            let dn = args.expand(&a.dn, Context::Dn)?;
            warn_unused(&args);
            let value = literal_value(&a.value)?;
            let ctrls = parse_controls(&a.t.control)?;
            let mut s = backend::connect(&resolved.connect)?;
            let r = s.compare(&dn, &a.attr, &value, &ctrls)?;
            match r.code {
                6 => {
                    println!("true");
                    Ok(())
                }
                5 => {
                    println!("false");
                    Err(Error::CompareFalse)
                }
                _ => r.into_result().map(|_| ()),
            }
        }
        Command::Exop(a) => exop(&ctx, a),
        Command::Whoami(t) => {
            let ctrls = parse_controls(&t.control)?;
            let mut s = backend::connect(&resolved.connect)?;
            println!("{}", whoami(s.as_mut(), &ctrls)?);
            Ok(())
        }
        Command::Passwd(a) => passwd(&ctx, a, &mut stdin),
        Command::Probe(a) => probe(&ctx, a),
        Command::Escape(_) | Command::Dn(_) => unreachable!(),
    }
}

struct Ctx<'a> {
    g: &'a Global,
    profile: &'a Profile,
    opts: &'a ConnectOptions,
}

fn warn_unused(args: &Args) {
    for u in args.unused() {
        eprintln!("warning: --arg {u} is not used by any template");
    }
}

/// `OID[!][=b64:VALUE]`
pub fn parse_controls(specs: &[String]) -> Result<Vec<Control>> {
    specs
        .iter()
        .map(|s| {
            let (head, value) = match s.split_once('=') {
                Some((h, v)) => {
                    let b = v.strip_prefix("b64:").ok_or_else(|| {
                        Error::usage(format!("control value in '{s}' must be b64:…"))
                    })?;
                    (h, Some(secret::decode_base64_lenient(b.as_bytes())?))
                }
                None => (s.as_str(), None),
            };
            let (oid, critical) = match head.strip_suffix('!') {
                Some(o) => (o, true),
                None => (head, false),
            };
            if oid.is_empty() || !oid.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Err(Error::usage(format!("invalid control OID in '{s}'")));
            }
            Ok(Control {
                oid: oid.to_string(),
                critical,
                value,
            })
        })
        .collect()
}

/// `b64:…` decodes base64; anything else is used literally.
fn literal_value(v: &str) -> Result<Vec<u8>> {
    match v.strip_prefix("b64:") {
        Some(b) => secret::decode_base64_lenient(b.as_bytes()),
        None => Ok(v.as_bytes().to_vec()),
    }
}

fn read_input(path: &str) -> Result<String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| Error::usage(format!("cannot read {path}: {e}")))
    }
}

// ---------------- RootDSE ----------------

fn root_dse(s: &mut dyn Session) -> Result<Entry> {
    let req = SearchRequest {
        base: String::new(),
        scope: Scope::Base,
        filter: "(objectClass=*)".into(),
        attrs: vec!["*".into(), "+".into()],
        types_only: false,
        size_limit: 0,
        time_limit: 0,
        deref: Deref::Never,
    };
    let mut entry = None;
    s.search(
        &req,
        &[],
        &mut |e| {
            entry = Some(e);
            Ok(())
        },
        &mut |_| Ok(()),
    )?
    .into_result()?;
    entry.ok_or_else(|| Error::ldap(32, "RootDSE not readable", ""))
}

fn has_value(e: &Entry, attr: &str, v: &str) -> bool {
    e.get_str(attr).iter().any(|x| x == v)
}

// ---------------- search ----------------

fn search(ctx: &Ctx, s: &mut dyn Session, a: SearchArgs) -> Result<()> {
    let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
    let filter_text = args.expand(&a.filter, Context::Filter)?;
    let filter = if a.raw_filter {
        filter_text
    } else {
        filter::normalize(&filter_text)?
    };
    let base = match a.base.clone().or(ctx.profile.base.clone()) {
        Some(b) => args.expand(&b, Context::Dn)?,
        None => default_base(s)?,
    };
    warn_unused(&args);
    let mut ctrls = parse_controls(&a.t.control)?;
    if !a.sort.is_empty() {
        ctrls.push(Control {
            oid: ber::OID_SORT_REQUEST.into(),
            critical: false,
            value: Some(ber::sort_request(&a.sort)?),
        });
    }
    let page_size = a.page_size.or(ctx.profile.page_size).unwrap_or(500);
    let req = SearchRequest {
        base,
        scope: a.scope.or(ctx.profile.scope).unwrap_or(Scope::Sub),
        filter,
        attrs: a.attrs.clone(),
        types_only: a.types_only,
        size_limit: a.size_limit,
        time_limit: a.time_limit,
        deref: a.deref,
    };
    if ctx.g.verbose {
        eprintln!(
            "search base=\"{}\" scope={:?} filter={}",
            req.base, req.scope, req.filter
        );
    }
    let format =
        ctx.g
            .format
            .or(ctx.profile.format)
            .unwrap_or(if std::io::stdout().is_terminal() {
                Format::Ldif
            } else {
                Format::Jsonl
            });
    let binary = ctx
        .g
        .binary
        .or(ctx.profile.binary)
        .unwrap_or(Binary::Base64);
    let mut out = Output::new(
        format,
        binary,
        ctx.g.ldif_wrap.unwrap_or(0),
        a.attrs.clone(),
    );

    let mut cookie: Vec<u8> = Vec::new();
    let final_result = loop {
        let mut page_ctrls = ctrls.clone();
        if page_size > 0 {
            page_ctrls.push(Control {
                oid: ber::OID_PAGED_RESULTS.into(),
                critical: false,
                value: Some(ber::paged_request(page_size, &cookie)),
            });
        }
        let mut entries = Vec::new();
        let mut refs = Vec::new();
        let r = s.search(
            &req,
            &page_ctrls,
            &mut |e| {
                entries.push(e);
                Ok(())
            },
            &mut |r| {
                refs.push(r);
                Ok(())
            },
        )?;
        for mut e in entries {
            if a.range == RangeMode::Auto {
                complete_ranges(s, &mut e)?;
            }
            out.entry(e)?;
        }
        for r in refs {
            out.reference(&r)?;
        }
        if r.code != 0 {
            break r;
        }
        match r
            .control(ber::OID_PAGED_RESULTS)
            .and_then(|c| c.value.as_ref())
        {
            Some(v) if page_size > 0 => {
                cookie = ber::paged_response(v)?;
                if cookie.is_empty() {
                    break r;
                }
            }
            _ => break r,
        }
    };
    let n = out.count();
    out.finish()?;
    if ctx.g.verbose {
        eprintln!("{n} entries");
    }
    final_result.into_result().map(|_| ())
}

fn default_base(s: &mut dyn Session) -> Result<String> {
    let dse = root_dse(s)?;
    if let Some(d) = dse.get_str("defaultNamingContext").into_iter().next() {
        return Ok(d);
    }
    let ncs = dse.get_str("namingContexts");
    match ncs.len() {
        1 => Ok(ncs[0].clone()),
        _ => Err(Error::usage(format!(
            "no --base given and the server has {} naming contexts; choose one: {}",
            ncs.len(),
            ncs.join(", ")
        ))),
    }
}

/// AD returns large multi-valued attributes in ranges (`member;range=0-1499`).
fn complete_ranges(s: &mut dyn Session, e: &mut Entry) -> Result<()> {
    let mut i = 0;
    while i < e.attrs.len() {
        let name = e.attrs[i].0.clone();
        let Some((base, range)) = name.split_once(";range=") else {
            i += 1;
            continue;
        };
        let base = base.to_string();
        let mut values = std::mem::take(&mut e.attrs[i].1);
        let mut end = range
            .split_once('-')
            .map(|x| x.1.to_string())
            .unwrap_or_else(|| "*".into());
        while end != "*" {
            let next: u64 = end
                .parse()
                .map_err(|_| Error::usage(format!("bad range in '{name}'")))?;
            let req = SearchRequest {
                base: e.dn.clone(),
                scope: Scope::Base,
                filter: "(objectClass=*)".into(),
                attrs: vec![format!("{base};range={}-*", next + 1)],
                types_only: false,
                size_limit: 0,
                time_limit: 0,
                deref: Deref::Never,
            };
            let mut got = None;
            s.search(
                &req,
                &[],
                &mut |x| {
                    got = Some(x);
                    Ok(())
                },
                &mut |_| Ok(()),
            )?
            .into_result()?;
            let Some(x) = got else { break };
            let Some((n, mut vs)) = x
                .attrs
                .into_iter()
                .find(|(n, _)| n.starts_with(&format!("{base};range=")))
            else {
                break;
            };
            values.append(&mut vs);
            end = n
                .rsplit_once('-')
                .map(|x| x.1.to_string())
                .unwrap_or_else(|| "*".into());
        }
        e.attrs[i] = (base, values);
        i += 1;
    }
    Ok(())
}

// ---------------- add / modify / delete / modrdn ----------------

fn parse_attr_value(spec: &str) -> Result<(String, Vec<u8>)> {
    let (k, v) = spec
        .split_once('=')
        .ok_or_else(|| Error::usage(format!("'{spec}' must be attr=value")))?;
    match k.strip_suffix(':') {
        Some(k) => Ok((
            k.to_string(),
            secret::decode_base64_lenient(v.strip_prefix("b64:").unwrap_or(v).as_bytes())?,
        )),
        None => Ok((k.to_string(), v.as_bytes().to_vec())),
    }
}

fn add_changes(a: &AddArgs) -> Result<Vec<Change>> {
    match (&a.file, &a.dn) {
        (Some(f), None) => ldif::parse(&read_input(f)?, true),
        (None, Some(dn)) => {
            let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
            let dn = args.expand(dn, Context::Dn)?;
            warn_unused(&args);
            let mut attrs: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
            for spec in &a.attrs {
                let (k, v) = parse_attr_value(spec)?;
                match attrs.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(&k)) {
                    Some((_, vs)) => vs.push(v),
                    None => attrs.push((k, vec![v])),
                }
            }
            if attrs.is_empty() {
                return Err(Error::usage("add needs at least one --attr"));
            }
            Ok(vec![Change::Add { dn, attrs }])
        }
        _ => Err(Error::usage("use either --file or --dn with --attr")),
    }
}

fn modify_changes(a: &ModifyArgs) -> Result<Vec<Change>> {
    match (&a.file, &a.dn) {
        (Some(f), None) => ldif::parse(&read_input(f)?, false),
        (None, Some(dn)) => {
            let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
            let dn = args.expand(dn, Context::Dn)?;
            warn_unused(&args);
            let mut mods = Vec::new();
            let mut push = |op: ModOp, specs: &[String], need_value: bool| -> Result<()> {
                for s in specs {
                    if !need_value && !s.contains('=') {
                        mods.push(Modification {
                            op,
                            attr: s.clone(),
                            values: vec![],
                        });
                        continue;
                    }
                    let (k, v) = parse_attr_value(s)?;
                    // Group consecutive values for the same attribute and operation.
                    match mods.last_mut() {
                        Some(m) if m.op == op && m.attr.eq_ignore_ascii_case(&k) => {
                            m.values.push(v)
                        }
                        _ => mods.push(Modification {
                            op,
                            attr: k,
                            values: vec![v],
                        }),
                    }
                }
                Ok(())
            };
            push(ModOp::Replace, &a.replace, true)?;
            push(ModOp::Add, &a.add, true)?;
            push(ModOp::Delete, &a.delete, false)?;
            push(ModOp::Increment, &a.increment, true)?;
            if mods.is_empty() {
                return Err(Error::usage(
                    "modify needs --add, --replace, --delete or --increment",
                ));
            }
            Ok(vec![Change::Modify { dn, mods }])
        }
        _ => Err(Error::usage("use either --file or --dn with operations")),
    }
}

fn describe(c: &Change) -> String {
    let mut s = String::new();
    match c {
        Change::Add { dn, attrs } => {
            ldif::write_line(&mut s, "dn", dn.as_bytes(), 0);
            s.push_str("changetype: add\n");
            for (a, vs) in attrs {
                for v in vs {
                    ldif::write_line(&mut s, a, v, 0);
                }
            }
        }
        Change::Modify { dn, mods } => {
            ldif::write_line(&mut s, "dn", dn.as_bytes(), 0);
            s.push_str("changetype: modify\n");
            for m in mods {
                let op = match m.op {
                    ModOp::Add => "add",
                    ModOp::Delete => "delete",
                    ModOp::Replace => "replace",
                    ModOp::Increment => "increment",
                };
                s.push_str(&format!("{op}: {}\n", m.attr));
                for v in &m.values {
                    let shown: &[u8] = if m.attr.eq_ignore_ascii_case("unicodePwd")
                        || m.attr.eq_ignore_ascii_case("userPassword")
                    {
                        b"********"
                    } else {
                        v
                    };
                    ldif::write_line(&mut s, &m.attr, shown, 0);
                }
                s.push_str("-\n");
            }
        }
        Change::Delete { dn } => {
            ldif::write_line(&mut s, "dn", dn.as_bytes(), 0);
            s.push_str("changetype: delete\n");
        }
        Change::ModRdn {
            dn,
            new_rdn,
            delete_old,
            new_superior,
        } => {
            ldif::write_line(&mut s, "dn", dn.as_bytes(), 0);
            s.push_str(&format!(
                "changetype: modrdn\nnewrdn: {new_rdn}\ndeleteoldrdn: {}\n",
                *delete_old as u8
            ));
            if let Some(n) = new_superior {
                s.push_str(&format!("newsuperior: {n}\n"));
            }
        }
    }
    s
}

fn apply(s: &mut dyn Session, c: &Change, ctrls: &[Control]) -> Result<OpResult> {
    match c {
        Change::Add { dn, attrs } => s.add(dn, attrs, ctrls),
        Change::Modify { dn, mods } => s.modify(dn, mods, ctrls),
        Change::Delete { dn } => s.delete(dn, ctrls),
        Change::ModRdn {
            dn,
            new_rdn,
            delete_old,
            new_superior,
        } => s.rename(dn, new_rdn, new_superior.as_deref(), *delete_old, ctrls),
    }
}

fn apply_all(
    ctx: &Ctx,
    changes: Vec<Change>,
    ctrls: &[Control],
    continue_on_error: bool,
) -> Result<()> {
    if ctx.g.dry_run {
        for c in &changes {
            println!("{}", describe(c));
        }
        return Ok(());
    }
    let mut s = backend::connect(ctx.opts)?;
    let mut first_err = None;
    for c in &changes {
        match apply(s.as_mut(), c, ctrls).and_then(|r| r.into_result()) {
            Ok(_) => {
                if ctx.g.verbose {
                    eprintln!("ok: {}", c.dn());
                }
            }
            Err(e) => {
                eprintln!("ldap: {}: {e}", c.dn());
                if !continue_on_error {
                    return Err(e);
                }
                first_err.get_or_insert(e);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn delete(ctx: &Ctx, a: DeleteArgs) -> Result<()> {
    let mut dns = a.dns.clone();
    if let Some(t) = &a.dn {
        let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
        dns.push(args.expand(t, Context::Dn)?);
        warn_unused(&args);
    }
    if let Some(f) = &a.file {
        dns.extend(
            read_input(f)?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    if dns.is_empty() {
        return Err(Error::usage("delete needs DNs, --dn or --file"));
    }
    for dn in &dns {
        escape::parse_dn(dn)?;
    }
    let mut ctrls = parse_controls(&a.t.control)?;
    if !a.subtree {
        return apply_all(
            ctx,
            dns.into_iter().map(|dn| Change::Delete { dn }).collect(),
            &ctrls,
            a.continue_on_error,
        );
    }
    let mut s = backend::connect(ctx.opts)?;
    let tree_delete = has_value(
        &root_dse(s.as_mut())?,
        "supportedControl",
        ber::OID_TREE_DELETE,
    );
    for dn in dns {
        let mut todo = Vec::new();
        if tree_delete {
            todo.push(dn.clone());
        } else {
            // Client-side: collect the subtree, delete deepest entries first.
            let req = SearchRequest {
                base: dn.clone(),
                scope: Scope::Sub,
                filter: "(objectClass=*)".into(),
                attrs: vec!["1.1".into()],
                types_only: false,
                size_limit: 0,
                time_limit: 0,
                deref: Deref::Never,
            };
            let mut cookie = Vec::new();
            loop {
                let pc = vec![Control {
                    oid: ber::OID_PAGED_RESULTS.into(),
                    critical: false,
                    value: Some(ber::paged_request(500, &cookie)),
                }];
                let r = s
                    .search(
                        &req,
                        &pc,
                        &mut |e| {
                            todo.push(e.dn);
                            Ok(())
                        },
                        &mut |_| Ok(()),
                    )?
                    .into_result()?;
                cookie = match r
                    .control(ber::OID_PAGED_RESULTS)
                    .and_then(|c| c.value.as_ref())
                {
                    Some(v) => ber::paged_response(v)?,
                    None => Vec::new(),
                };
                if cookie.is_empty() {
                    break;
                }
            }
            todo.sort_by_key(|d| {
                std::cmp::Reverse(escape::parse_dn(d).map(|r| r.len()).unwrap_or(0))
            });
        }
        let mut c = ctrls.clone();
        if tree_delete {
            c.push(Control {
                oid: ber::OID_TREE_DELETE.into(),
                critical: true,
                value: None,
            });
        }
        for d in todo {
            if ctx.g.dry_run {
                println!("{}", describe(&Change::Delete { dn: d }));
                continue;
            }
            if let Err(e) = s.delete(&d, &c).and_then(|r| r.into_result()) {
                eprintln!("ldap: {d}: {e}");
                if !a.continue_on_error {
                    return Err(e);
                }
            } else if ctx.g.verbose {
                eprintln!("deleted: {d}");
            }
        }
    }
    ctrls.clear();
    Ok(())
}

// ---------------- extended operations ----------------

fn whoami(s: &mut dyn Session, ctrls: &[Control]) -> Result<String> {
    let r = s.extended(ber::OID_WHOAMI, None, ctrls)?;
    r.result.clone().into_result()?;
    let id = r
        .value
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default();
    Ok(if id.is_empty() {
        "anonymous".into()
    } else {
        id
    })
}

fn exop(ctx: &Ctx, a: ExopArgs) -> Result<()> {
    let ctrls = parse_controls(&a.t.control)?;
    let (oid, value) = match a.op.as_str() {
        "whoami" => (ber::OID_WHOAMI.to_string(), None),
        "cancel" => {
            let id: i64 = a
                .value
                .as_deref()
                .ok_or_else(|| Error::usage("cancel needs --value MSGID"))?
                .parse()
                .map_err(|_| Error::usage("--value must be a message ID"))?;
            (ber::OID_CANCEL.to_string(), Some(ber::cancel_request(id)))
        }
        "refresh" => {
            let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
            let dn = args.expand(
                a.value
                    .as_deref()
                    .ok_or_else(|| Error::usage("refresh needs --value DN"))?,
                Context::Dn,
            )?;
            let ttl = a.ttl.ok_or_else(|| Error::usage("refresh needs --ttl"))?;
            let mut ttl_enc = ber::integer(ttl as i64);
            ttl_enc[0] = 0x81;
            (
                ber::OID_REFRESH.to_string(),
                Some(ber::sequence(&[ber::tlv(0x80, dn.as_bytes()), ttl_enc])),
            )
        }
        oid if oid.chars().all(|c| c.is_ascii_digit() || c == '.') => (
            oid.to_string(),
            a.value.as_deref().map(literal_value).transpose()?,
        ),
        other => {
            return Err(Error::usage(format!(
                "unknown extended operation '{other}'"
            )));
        }
    };
    let mut s = backend::connect(ctx.opts)?;
    let r = s.extended(&oid, value.as_deref(), &ctrls)?;
    r.result.clone().into_result()?;
    if let Some(o) = &r.oid {
        println!("oid: {o}");
    }
    if let Some(v) = &r.value {
        match std::str::from_utf8(v) {
            Ok(t) if !t.contains('\0') => println!("value: {t}"),
            _ => println!("value:: {}", B64.encode(v)),
        }
    }
    Ok(())
}

// ---------------- passwd ----------------

fn generate_password(len: usize) -> Result<String> {
    const SETS: [&[u8]; 4] = [
        b"ABCDEFGHJKLMNPQRSTUVWXYZ",
        b"abcdefghijkmnopqrstuvwxyz",
        b"23456789",
        b"!#%+-.=?@_~",
    ];
    if len < 8 {
        return Err(Error::usage("--generate needs a length of at least 8"));
    }
    let all: Vec<u8> = SETS.concat();
    loop {
        let mut buf = vec![0u8; len * 2];
        getrandom::fill(&mut buf)
            .map_err(|e| Error::usage(format!("random generator failed: {e}")))?;
        // Rejection sampling to avoid modulo bias.
        let limit = 256 - 256 % all.len();
        let pw: String = buf
            .iter()
            .filter(|b| (**b as usize) < limit)
            .take(len)
            .map(|b| all[*b as usize % all.len()] as char)
            .collect();
        if pw.len() == len && SETS.iter().all(|set| pw.bytes().any(|c| set.contains(&c))) {
            return Ok(pw);
        }
    }
}

fn passwd(ctx: &Ctx, a: PasswdArgs, stdin: &mut StdinGuard) -> Result<()> {
    let _ = stdin; // stdin was already claimed for --new-password-stdin
    let args = Args::parse(&a.t.arg, &a.t.arg_file)?;
    let target =
        a.dn.as_deref()
            .map(|d| args.expand(d, Context::Dn))
            .transpose()?;
    warn_unused(&args);
    let n_sources = [
        a.new_password_file.is_some(),
        a.new_password_env.is_some(),
        a.new_password_stdin,
        a.generate.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if n_sources > 1 {
        return Err(Error::usage(
            "give one of --new-password-file, --new-password-env, --new-password-stdin, --generate",
        ));
    }
    let mut generated = None;
    let new = if let Some(n) = a.generate {
        let pw = generate_password(n)?;
        generated = Some(pw.clone());
        Secret::new(pw.into_bytes())
    } else if let Some(f) = &a.new_password_file {
        secret::read_password(&Source::File(f.clone()))?
    } else if let Some(v) = &a.new_password_env {
        secret::read_password(&Source::Env(v.clone()))?
    } else if a.new_password_stdin {
        secret::read_password(&Source::Stdin)?
    } else {
        let p1 = secret::read_password(&Source::Prompt("New password".into()))?;
        let p2 = secret::read_password(&Source::Prompt("Repeat new password".into()))?;
        if p1.bytes() != p2.bytes() {
            return Err(Error::usage("passwords do not match"));
        }
        p1
    };
    let old = if let Some(f) = &a.old_password_file {
        Some(secret::read_password(&Source::File(f.clone()))?)
    } else if let Some(v) = &a.old_password_env {
        Some(secret::read_password(&Source::Env(v.clone()))?)
    } else if a.old_password_prompt {
        Some(secret::read_password(&Source::Prompt(
            "Old password".into(),
        ))?)
    } else {
        None
    };
    let encrypted = ctx.opts.tls.mode != TlsMode::None || ctx.opts.auth.qos == Qos::Seal;
    if !encrypted {
        return Err(Error::usage(
            "passwd refuses to send passwords without TLS or a sealed SASL connection",
        ));
    }
    let ctrls = parse_controls(&a.t.control)?;
    let mut s = backend::connect(ctx.opts)?;
    let method = match a.method {
        PasswdMethod::Auto => {
            let dse = root_dse(s.as_mut())?;
            if has_value(&dse, "supportedExtension", ber::OID_PASSWD_MODIFY) {
                PasswdMethod::Exop
            } else if has_value(&dse, "supportedCapabilities", ber::OID_AD_CAPABILITY) {
                PasswdMethod::Ad
            } else {
                return Err(Error::usage(
                    "server supports neither RFC 3062 nor AD unicodePwd; use --method replace",
                ));
            }
        }
        m => m,
    };
    match method {
        PasswdMethod::Exop => {
            let v = ber::passwd_request(
                target.as_deref(),
                old.as_ref().map(|o| o.bytes()),
                Some(new.bytes()),
            );
            let r = s.extended(ber::OID_PASSWD_MODIFY, Some(&v), &ctrls)?;
            r.result.clone().into_result()?;
            if let Some(generated_pw) = r
                .value
                .as_deref()
                .map(ber::passwd_response)
                .transpose()?
                .flatten()
            {
                println!("{}", String::from_utf8_lossy(&generated_pw));
            }
        }
        PasswdMethod::Ad => {
            let dn = target.ok_or_else(|| {
                Error::usage("--method ad needs --dn (AD reports identities as DOMAIN\\user)")
            })?;
            let enc = |p: &Secret| -> Result<Vec<u8>> { Ok(crate::ad::unicode_pwd(p.as_str()?)) };
            let mods = match &old {
                Some(o) => vec![
                    Modification {
                        op: ModOp::Delete,
                        attr: "unicodePwd".into(),
                        values: vec![enc(o)?],
                    },
                    Modification {
                        op: ModOp::Add,
                        attr: "unicodePwd".into(),
                        values: vec![enc(&new)?],
                    },
                ],
                None => vec![Modification {
                    op: ModOp::Replace,
                    attr: "unicodePwd".into(),
                    values: vec![enc(&new)?],
                }],
            };
            s.modify(&dn, &mods, &ctrls)?.into_result()?;
        }
        PasswdMethod::Replace => {
            let dn = target.ok_or_else(|| Error::usage("--method replace needs --dn"))?;
            let mods = vec![Modification {
                op: ModOp::Replace,
                attr: "userPassword".into(),
                values: vec![new.bytes().to_vec()],
            }];
            s.modify(&dn, &mods, &ctrls)?.into_result()?;
        }
        PasswdMethod::Auto => unreachable!(),
    }
    if let Some(pw) = generated {
        println!("{pw}");
    }
    Ok(())
}

// ---------------- probe ----------------

fn probe(ctx: &Ctx, a: ProbeArgs) -> Result<()> {
    let mut s = backend::connect(ctx.opts)?;
    let info = s.info();
    println!("server: {}:{}", info.host, info.port);
    println!(
        "tls: {}",
        if info.tls {
            info.tls_version.clone().unwrap_or_else(|| "yes".into())
        } else {
            "no".into()
        }
    );
    for (i, (der, subject)) in info.peer_chain.iter().enumerate() {
        let fp = sha2::Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        println!("cert[{i}]: {subject}\n  sha256: {fp}");
    }
    match whoami(s.as_mut(), &[]) {
        Ok(id) => println!("bound as: {id}"),
        Err(e) => println!("bound as: (whoami not available: {e})"),
    }
    let dse = root_dse(s.as_mut())?;
    let is_ad = has_value(&dse, "supportedCapabilities", ber::OID_AD_CAPABILITY);
    println!("active directory: {}", if is_ad { "yes" } else { "no" });
    for attr in [
        "vendorName",
        "vendorVersion",
        "dnsHostName",
        "defaultNamingContext",
        "namingContexts",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "supportedExtension",
        "supportedControl",
        "domainControllerFunctionality",
    ] {
        for v in dse.get_str(attr) {
            println!("{attr}: {v}");
        }
    }
    println!(
        "password change: {}",
        if has_value(&dse, "supportedExtension", ber::OID_PASSWD_MODIFY) {
            "exop (RFC 3062)"
        } else if is_ad {
            "ad (unicodePwd)"
        } else {
            "replace only"
        }
    );
    if a.print_ca {
        let (der, subject) = info
            .peer_chain
            .last()
            .ok_or_else(|| Error::usage("no certificate chain captured (is TLS on?)"))?;
        eprintln!("top of the presented chain: {subject}");
        eprintln!("verify this fingerprint out of band before trusting it:");
        eprintln!(
            "  sha256: {}",
            sha2::Sha256::digest(der)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        );
        println!("{}", B64.encode(der));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls() {
        let c = parse_controls(&[
            "1.2.3!".into(),
            "1.2.840.113556.1.4.801=b64:MAMCAQc=".into(),
        ])
        .unwrap();
        assert!(c[0].critical && c[0].value.is_none());
        assert_eq!(c[1].value.as_deref(), Some(&[0x30, 3, 2, 1, 7][..]));
        assert!(parse_controls(&["x.y".into()]).is_err());
        assert!(parse_controls(&["1.2=raw".into()]).is_err());
    }

    #[test]
    fn generated_passwords() {
        let p = generate_password(16).unwrap();
        assert_eq!(p.len(), 16);
        assert!(p.bytes().any(|c| c.is_ascii_digit()));
        assert!(generate_password(4).is_err());
    }

    #[test]
    fn attr_values() {
        assert_eq!(
            parse_attr_value("cn=a=b").unwrap(),
            ("cn".into(), b"a=b".to_vec())
        );
        assert_eq!(
            parse_attr_value("photo:=b64:AAE=").unwrap(),
            ("photo".into(), vec![0, 1])
        );
        assert!(parse_attr_value("cn").is_err());
    }
}
