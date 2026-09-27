//! SQL and NoSQL injection.

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Low,
    Paranoid,
};
use crate::domain::rules::{
    FieldCondition,
    WafAction,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    PAYLOAD_FIELDS,
    PAYLOAD_PATH_FIELDS,
    URL_FIELDS,
    any_field_matches,
    re,
};

/// Classic high-signal SQLi (UNION / boolean equality). Active from `Low`.
const SQLI_CLASSIC: &str = concat!(
    r#"(?:\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|\b(?:INTERSECT|"#,
    r#"EXCEPT)\b\s+\bSELECT\b|\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|＇)"#,
);

/// Time-based / stacked / schema probes — higher false-positive risk on noisy
/// apps. Active from `High`.
const SQLI_ADVANCED: &str = concat!(
    r"(?:\bAND\b\s+EXTRACTVALUE\b|\b(?:SLEEP|BENCHMARK|WAITFOR|",
    r"RLIKE)\b\s*[\s(]|\bINFORMATION_SCHEMA\b|;\s*(?:SELECT|DECLARE|WAITFOR|",
    r"CREATE)\b|(?:^|[\s)])(?:OR|AND)\s+(?:SELECT|UNION|DECLARE|INSERT|UPDATE|",
    r"DELETE|WAITFOR)\b)",
);

/// DBMS fingerprinting plus file / command primitives (CRS 942140 / 942190).
const SQLI_DBMS_PRIMITIVES: &str = concat!(
    r"(?:@@(?:version|datadir|hostname|basedir|tmpdir)\b|\bload_file\s*\(|",
    r"\binto\s+(?:out|dump)file\b|\bxp_cmdshell\b|\bsp_executesql\b|",
    r"\bpg_sleep\s*\(|\bdbms_pipe\s*\.|\butl_inaddr\b|\bsys_context\s*\(|",
    r"\bopenrowset\s*\(|\bsysdatabases\b|\bsysusers\b)",
);

/// MySQL versioned comment used to smuggle keywords (CRS 942500). URL-borne
/// fields only: minified JavaScript keeps `/*!` license banners.
const SQLI_VERSIONED_COMMENT: &str = r"\/\*!(?:\d{5})?|\/\*%21";

/// Quoted tautologies the numeric `OR 1=1` pattern misses.
const SQLI_TAUTOLOGY: &str = concat!(
    r#"['"`]\s*\)?\s*(?:OR|AND|XOR|\|\||"#,
    r#"&&)\s*\(?\s*['"`]?[\w.]{1,24}['"`]?\s*(?:=|<>|!=|<=>|"#,
    r#"\bLIKE\b)\s*['"`]?[\w.]{1,24}['"`]?"#,
);

/// A full `SELECT … FROM <identifier>` projection in URL-borne input (CRS
/// 942360).
const SQLI_SELECT_FROM: &str =
    r#"\bSELECT\b[\s\S]{1,160}?\bFROM\b\s*[\w."`\[]"#;

/// Whitespace-free nested subquery — `(select(0)from(select(sleep(1)))x)`.
const SQLI_COMPACT_SUBQUERY: &str = r"\bselect\s*\([\s\S]{0,80}?\bfrom\s*\(";

/// MySQL / MariaDB JSON accessors used to read data during injection.
const SQLI_JSON_FUNCTION: &str = concat!(
    r"\bjson_(?:extract|keys|depth|contains(?:_path)?|search|value|query|",
    r"arrayagg|objectagg|table|valid|unquote|length|overlaps|storage_(?:size|",
    r"free)|merge(?:_preserve|_patch)?)\s*\(",
);

/// MongoDB driver / shell method calls — `db.users.find(`.
const NOSQL_DRIVER_API: &str = concat!(
    r"\bdb\.\w{1,40}\.(?:find(?:One)?(?:AndModify|AndUpdate|AndDelete|",
    r"AndReplace)?|insert(?:One|Many)?|update(?:One|Many)?|delete(?:One|",
    r"Many)?|replaceOne|remove|save|aggregate|mapReduce|count(?:Documents)?|",
    r"distinct|bulkWrite)\s*\(",
);

/// MongoDB operator injection in quoted-JSON and bracketed query forms (CRS
/// 942290).
const NOSQL_OPERATOR: &str = concat!(
    r#"(?:["']\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|function|nin|in|all|"#,
    r#"elemMatch|jsonSchema)\s*["']\s*:|\[\s*\$(?:where|ne|gt|gte|lt|lte|"#,
    r#"regex|expr|function)\s*\]|(?:^|[&\[])\$(?:where|ne|gt|gte|lt|lte|"#,
    r#"regex|expr|function)\s*[=\]])"#,
);

/// NoSQL operator injection in bare (unquoted) form — `$where: '…'`,
/// `{$gt: ''}`. The leading bracket keeps `${var}` templates out.
const NOSQL_STRING: &str = concat!(
    r"\$where\s*:|(?:^|[,{\[(])\s*\$(?:or|and|nor|not|gt|gte|lt|lte|ne|nin|in|",
    r"regex|expr|function|elemMatch|jsonSchema)\s*:",
);

/// Keyword-free numeric boolean test — `AND 1=1`, `123) AND 12=12`.
const SQLI_BOOLEAN_EQUALITY: &str =
    r"\b(?:AND|OR|XOR)\b\s*\(?\s*\d{1,6}\s*(?:=|!=|<=>|>=|<=)\s*\d{1,6}";

/// Blind / boolean / enumeration probes (CRS 942130 / 942210).
const SQLI_BLIND: &str = concat!(
    r#"(?:\b(?:ORDER|GROUP)\s+BY\s+\d{1,4}\s*(?:--|#|;|\/\*|\)|$)|"#,
    r#"\bHAVING\b\s*\d{1,4}\s*=\s*\d{1,4}|"#,
    r#"\bCASE\s+WHEN\b[\s\S]{0,80}?\bTHEN\b|\b(?:AND|OR)\s*\(\s*SELECT\b|"#,
    r#"\bIF\s*\(\s*(?:\d{1,4}\s*[=<>]|ASCII\s*\(|SUBSTR)|"#,
    r#"\bCHAR\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}\s*\)|"#,
    r#"['"`]\s*\)*\s*(?:;\s*)?--(?:\s|$))"#,
);

/// MongoDB `$where` infinite busy loop.
const NOSQL_TIMEBOMB: &str =
    r"\bwhile\s*\(\s*(?:true|1|!0|0x1)\s*\)|\bfor\(\s*;\s*;\s*\)";

/// MongoDB `$where` timing DoS: a `new Date()` delta driving a loop condition.
const NOSQL_TIME_DOS: &str =
    r"\bnew\s+Date\s*\([^)]*\)[\s\S]{0,120}?\bwhile\s*\(\s*[\w.]+\s*-\s*[\w.]+";

/// T-SQL local-variable declaration — the opening of a stacked-query payload.
const MSSQL_DECLARE: &str = concat!(
    r"\bDECLARE\s+@\w+\s+(?:var|n)?(?:char|binary)\b|",
    r"\bDECLARE\s+@\w+\s+(?:big|small|tiny)?int\b|\bDECLARE\s+@\w+\s+(?:table|",
    r"cursor|xml|money|bit|float|real|uniqueidentifier|date(?:time(?:2|",
    r"offset)?|)?|time)\b",
);

fn field_rules(kind: &str, pattern: &str) -> Vec<WafRule> {
    let pattern = re(pattern, "i");
    let (min_level, label) = if kind == "classic" {
        (Low, "SQL injection")
    } else {
        (High, "advanced SQL injection")
    };
    [
        (WafField::Query, "query", "query string"),
        (WafField::Body, "body", "body"),
        (WafField::Path, "path", "path"),
        (WafField::Cookies, "cookies", "cookies"),
    ]
    .into_iter()
    .map(|(field, name, label_field)| {
        WafRule::new(
            format!("preset-sqli-{kind}-{name}"),
            FieldCondition::new(field).matches(pattern.clone()),
            WafAction::Block,
        )
        .priority(50)
        .min_level(min_level)
        .reason(format!("Possible {label} in {label_field}"))
    })
    .collect()
}

fn rules() -> Vec<WafRule> {
    let mut rules = field_rules("classic", SQLI_CLASSIC);
    rules.extend(field_rules("advanced", SQLI_ADVANCED));
    rules.extend([
        WafRule::new(
            "preset-sqli-dbms-primitives",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(SQLI_DBMS_PRIMITIVES, "i"),
                &[
                    "@@",
                    "load_file",
                    "outfile",
                    "dumpfile",
                    "xp_cmdshell",
                    "sp_executesql",
                    "pg_sleep",
                    "dbms_pipe",
                    "utl_inaddr",
                    "sys_context",
                    "openrowset",
                    "sysdatabases",
                    "sysusers",
                ],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Low)
        .reason("SQL injection using DBMS file or command primitives"),
        WafRule::new(
            "preset-sqli-versioned-comment",
            any_field_matches(
                &URL_FIELDS,
                &re(SQLI_VERSIONED_COMMENT, "i"),
                &["/*!", "/*%21"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Low)
        .reason("MySQL versioned comment used to obfuscate SQL"),
        WafRule::new(
            "preset-sqli-tautology",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(SQLI_TAUTOLOGY, "i"),
                &[],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible SQL injection tautology"),
        WafRule::new(
            "preset-sqli-select-from",
            any_field_matches(
                &URL_FIELDS,
                &re(SQLI_SELECT_FROM, "i"),
                &["select"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("SQL SELECT … FROM projection in URL-borne input"),
        WafRule::new(
            "preset-sqli-nosql-operator",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(NOSQL_OPERATOR, "i"),
                &["$"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible NoSQL (MongoDB) operator injection"),
        WafRule::new(
            "preset-sqli-nosql-string",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(NOSQL_STRING, "i"),
                &["$"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible NoSQL operator injection (unquoted form)"),
        WafRule::new(
            "preset-sqli-boolean-equality",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(SQLI_BOOLEAN_EQUALITY, "i"),
                &["="],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(High)
        .reason(
            "Possible boolean-based blind SQL injection (numeric equality)",
        ),
        WafRule::new(
            "preset-sqli-compact-subquery",
            any_field_matches(
                &URL_FIELDS,
                &re(SQLI_COMPACT_SUBQUERY, "i"),
                &["select"],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(High)
        .reason("Possible SQL injection via whitespace-free nested subquery"),
        WafRule::new(
            "preset-sqli-json-functions",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(SQLI_JSON_FUNCTION, "i"),
                &["json_"],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(High)
        .reason("Possible SQL injection using JSON accessor functions"),
        WafRule::new(
            "preset-sqli-nosql-driver-api",
            any_field_matches(
                &[WafField::Query, WafField::Body, WafField::Path],
                &re(NOSQL_DRIVER_API, "i"),
                &["db."],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(High)
        .reason("Possible NoSQL injection via MongoDB driver API call"),
        WafRule::new(
            "preset-sqli-blind",
            any_field_matches(&PAYLOAD_PATH_FIELDS, &re(SQLI_BLIND, "i"), &[]),
            WafAction::Block,
        )
        .priority(52)
        .min_level(High)
        .reason("Possible blind / enumeration SQL injection"),
        WafRule::new(
            "preset-sqli-nosql-time-dos",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(NOSQL_TIME_DOS, "i"),
                &["new date"],
            ),
            WafAction::Block,
        )
        .priority(54)
        .min_level(High)
        .reason("Possible NoSQL $where timing denial-of-service loop"),
        WafRule::new(
            "preset-sqli-nosql-timebomb",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(NOSQL_TIMEBOMB, "i"),
                &["while", "for("],
            ),
            WafAction::Block,
        )
        .priority(54)
        .min_level(Paranoid)
        .reason("Possible NoSQL $where JavaScript denial-of-service loop"),
        WafRule::new(
            "preset-sqli-mssql-declare",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(MSSQL_DECLARE, "i"),
                &["declare"],
            ),
            WafAction::Block,
        )
        .priority(56)
        .min_level(Paranoid)
        .reason("Possible stacked-query SQL injection via T-SQL DECLARE"),
    ]);
    rules
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `sqli` preset.
pub fn sqli_rules() -> &'static [WafRule] {
    &RULES
}
