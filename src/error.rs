//! Error type and exit codes.
//!
//! Exit codes: 0 success, 1 compare false, 2 usage, 3 connection/TLS, 4 authentication,
//! 10 + LDAP result code for other LDAP errors.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Usage(String),
    Connect(String),
    Auth(String),
    Ldap {
        code: i32,
        message: String,
        matched: String,
    },
    CompareFalse,
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn usage(m: impl Into<String>) -> Self {
        Error::Usage(m.into())
    }
    pub fn connect(m: impl Into<String>) -> Self {
        Error::Connect(m.into())
    }
    pub fn auth(m: impl Into<String>) -> Self {
        Error::Auth(m.into())
    }
    pub fn ldap(code: i32, message: impl Into<String>, matched: impl Into<String>) -> Self {
        Error::Ldap {
            code,
            message: message.into(),
            matched: matched.into(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::CompareFalse => 1,
            Error::Usage(_) => 2,
            Error::Connect(_) | Error::Io(_) => 3,
            Error::Auth(_) => 4,
            Error::Ldap { code, .. } => 10 + code.clamp(&0, &245),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "{m}"),
            Error::Connect(m) => write!(f, "connection failed: {m}"),
            Error::Auth(m) => write!(f, "authentication failed: {m}"),
            Error::Ldap {
                code,
                message,
                matched,
            } => {
                write!(f, "{} ({code})", result_name(*code))?;
                if !message.is_empty() {
                    write!(f, ": {message}")?;
                }
                if !matched.is_empty() {
                    write!(f, " [matched DN: {matched}]")?;
                }
                Ok(())
            }
            Error::CompareFalse => write!(f, "compare false"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn result_name(code: i32) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        5 => "compareFalse",
        6 => "compareTrue",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        10 => "referral",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        14 => "saslBindInProgress",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        18 => "inappropriateMatching",
        19 => "constraintViolation",
        20 => "attributeOrValueExists",
        21 => "invalidAttributeSyntax",
        32 => "noSuchObject",
        33 => "aliasProblem",
        34 => "invalidDNSyntax",
        36 => "aliasDereferencingProblem",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        54 => "loopDetect",
        64 => "namingViolation",
        65 => "objectClassViolation",
        66 => "notAllowedOnNonLeaf",
        67 => "notAllowedOnRDN",
        68 => "entryAlreadyExists",
        69 => "objectClassModsProhibited",
        71 => "affectsMultipleDSAs",
        80 => "other",
        81 => "serverDown",
        85 => "timeout",
        _ => "ldapError",
    }
}

/// Active Directory packs the real reason into the diagnostic message as "data XXX".
/// Translate the common ones for bind failures.
pub fn ad_bind_hint(message: &str) -> Option<&'static str> {
    let code = message.split("data ").nth(1)?.get(0..3)?;
    Some(match code {
        "525" => "user not found",
        "52e" => "invalid credentials",
        "530" => "logon not permitted at this time",
        "531" => "logon not permitted from this workstation",
        "532" => "password expired",
        "533" => "account disabled",
        "701" => "account expired",
        "773" => "user must reset password",
        "775" => "account locked out",
        _ => return None,
    })
}
