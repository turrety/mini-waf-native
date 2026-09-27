//! Remote code execution, SSTI and SSRF (CRS REQUEST-932 / 934).

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Low,
    Paranoid,
};
use crate::domain::rules::{
    WafAction,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    PAYLOAD_FIELDS,
    any_field_matches,
    re,
};

/// Unix command injection. Two arms, because separator strength differs:
/// an unambiguous separator (`;`, backtick, `$(`, `&&`, `||`, newline) before
/// any shell binary, or a bare `|` that also needs a non-ambiguous binary
/// **and** an argument (pipe-delimited values like `rails|php|node` exist).
const UNIX_CMD_INJECTION: &str = concat!(
    r#"(?:[;`\n]|\$\(|&&|\|\|)\s*\/?(?:\w+\/)*(?:cat|chmod|chown|curl|wget|"#,
    r#"bash|dash|zsh|sh|nc|ncat|netcat|python[23]?|perl|ruby|php|id|whoami|"#,
    r#"uname|ls|rm|kill|sleep|ping|telnet|ftp|busybox|xterm|crontab|nohup|"#,
    r#"getent|dig|nslookup)\b|\|\s*\/?(?:\w+\/)*(?:chmod|chown|curl|wget|nc|"#,
    r#"ncat|netcat|whoami|uname|busybox|xterm|telnet|crontab|nohup|bash|sh|"#,
    r#"python[23]?|perl|getent)\s+[-\w'"/]"#,
);

/// PowerShell / cmd.exe probes.
const WINDOWS_RCE: &str = concat!(
    r"\b(?:cmd(?:\.exe)?\b[^&\n|]*\s\/[ck]\b|powershell(?:\.exe)?\b[^&\n|",
    r"]*-(?:encodedcommand|e(?:c)?|command|c)\b|invoke-expression\b|",
    r"\biex\s*\()",
);

/// cmd.exe `set /a` (arithmetic) and `set /p` (prompt) primitives.
const WINDOWS_CMD_SET: &str = r"\bset\s+\/[ap]\b";

/// Living-off-the-land Windows binaries, each with its dangerous flag.
const WINDOWS_LOLBIN: &str = concat!(
    r"\b(?:certutil(?:\.exe)?\b[^\n]{0,80}-(?:urlcache|decode|encode)\b|",
    r"bitsadmin(?:\.exe)?\b[^\n]{0,60}\/transfer\b|",
    r"mshta(?:\.exe)?\s+(?:https?|javascript|vbscript)\s*:|",
    r"regsvr32(?:\.exe)?\b[^\n]{0,60}\/i\s*:|",
    r"wmic\b[^\n]{0,60}\bprocess\b[^\n]{0,40}\bcall\b[^\n]{0,20}\bcreate\b|",
    r"msiexec(?:\.exe)?\b[^\n]{0,40}\/i\s+https?\s*:)",
);

/// Shellshock bash function export (CRS 932170/171).
const SHELLSHOCK: &str = r"\(\s*\)\s*\{";

/// JNDI / Log4Shell lookup, including nested `${${lower:j}ndi:` obfuscation.
const JNDI_LOOKUP: &str = concat!(
    r"\$\{\s*(?:jndi|ctx|env|sys|lower|upper|date|main|java|base64|url|",
    r"spring)\s*:|\$\{[^}]{0,40}\$\{",
);

/// Reverse / bind shell staging.
const REVERSE_SHELL: &str = concat!(
    r"\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-[a-z]{0,3}e\b|",
    r"\b(?:ba|z|k)?sh\s+-[a-z]{0,3}i\b[^\n]{0,20}>\s*&|",
    r"\bsocat\b[^\n]{0,60}\bexec\s*:|\bmkfifo\b[^\n]{0,60}\bn(?:c|cat)\b|",
    r"\bmsfvenom\b",
);

/// Fetch-and-run: `curl … | sh`, `base64 -d | bash`, `python -c '…'`.
const DOWNLOAD_EXEC: &str = concat!(
    r#"\b(?:curl|wget|fetch)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|da|"#,
    r#"k)?sh\b|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,60}\|\s*(?:ba)?sh\b|"#,
    r#"\b(?:python[23]?|perl|ruby|node|php)\s+-(?:c|e|r)\s+["'`]"#,
);

/// SSTI with execution indicators (CRS 934200 simplified).
const SSTI: &str = concat!(
    r"\{\{[^}]{0,80}?(?:\*|__|\()[^}]{0,80}?\}\}|#\{[^}]{0,80}?(?:\*|__|",
    r"\()[^}]{0,80}?\}|<%[=]?[^%]{0,80}?(?:\*|__|\()[^%]{0,80}?%>",
);

/// Cloud metadata / link-local SSRF targets (CRS 934110 subset).
const SSRF_METADATA: &str = concat!(
    r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|",
    r"192\.0\.0\.192|instance-data\/latest|computeMetadata\/v1|",
    r"169\.254\.170\.2\/v2)",
);

/// SSRF to a private / loopback host through a URL scheme. `Paranoid`:
/// internal webhooks and dev callbacks look the same.
const SSRF_INTERNAL: &str = concat!(
    r"\b(?:https?|ftp|gopher|dict|",
    r"ldap):\/\/(?:[^/\s@]{0,80}@)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|",
    r"0\.0\.0\.0|localhost|\[?::1\]?|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|",
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
);

/// VBScript / ASP string-concatenation obfuscation — `Ex"&"e"&"cute`.
const ASP_STRING_CONCAT: &str = r#"(?:["'][&+]["'][a-z0-9]{0,3}){2,}"#;

/// Node.js `child_process` / dynamic `require` injection.
const NODE_RCE: &str = concat!(
    r#"\brequire\s*\(\s*['"]child_process['"]|"#,
    r#"\bchild_process\b[\s\S]{0,40}\b(?:exec(?:Sync)?|spawn(?:Sync)?)\s*\("#,
);

/// Language-level process execution APIs (Python, Java, Ruby).
const LANG_EXEC: &str = concat!(
    r#"\bos\s*\.\s*(?:system|popen|execv?p?e?)\s*\(|"#,
    r#"\bsubprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)\s*\(|"#,
    r#"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|"#,
    r#"\bProcessBuilder\s*\(|\b__import__\s*\(\s*["']os["']|"#,
    r#"\bcommands\s*\.\s*getoutput\s*\(|\bIO\s*\.\s*popen\s*\("#,
);

/// Serialized-object payloads that lead to gadget-chain RCE.
///
/// Every arm carries one of the rule's `requires` literals. The prefilter
/// matters here: seven case-insensitive arms exceed the regex engine's literal
/// budget, so without it a clean 8 KB body costs ~135 µs instead of ~1 µs.
const DESERIALIZATION: &str = concat!(
    r#"\brO0AB[A-Za-z0-9+/]{4}|\baced0005\b|"#,
    r#"\bO:\d{1,3}:"[A-Za-z_\\][\w\\]{0,60}":\d{1,4}:\{|"#,
    r#"\ba:\d{1,4}:\{[is]:\d|\bpickle\s*\.\s*loads\s*\(|"#,
    r#"\byaml\s*\.\s*(?:unsafe_)?load\s*\(|\b__reduce__\b"#,
);

/// Shell parameter expansion / process substitution. A bare `${name}` needs
/// an expansion operator, so i18n and price templates stay clean.
const SHELL_EXPANSION: &str = concat!(
    r"\$\([^)]{1,120}\)|<\([^)]{1,80}\)|\$\{IFS\}|\$\{[!#]|",
    r"\$\{\w{1,32}[:#%/^,][^}]{0,80}\}",
);

/// Fork bomb.
const FORK_BOMB: &str = r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:";

/// FreeMarker template injection.
const FREEMARKER: &str = concat!(
    r#"<#\s*(?:assign|list|if|include|import|macro|function|global|local|"#,
    r#"setting)\b|freemarker\.template\.utility\.(?:Execute|"#,
    r#"ObjectConstructor)|\?\s*new\s*\(\s*["'][\w.]*(?:Execute|"#,
    r#"ObjectConstructor)"#,
);

/// Unsafe deserialization tags for PyYAML, Ruby YAML and Java.
const YAML_UNSAFE_TAG: &str = concat!(
    r"!!python\/(?:object|module|name)\b|!ruby\/(?:object|hash|struct|marshal|",
    r"range)\b|!!(?:java|javax)\.",
);

fn rules() -> Vec<WafRule> {
    let payload_and_headers = [
        WafField::Query,
        WafField::Body,
        WafField::Cookies,
        WafField::Headers,
    ];
    let payload_and_path = [
        WafField::Query,
        WafField::Body,
        WafField::Cookies,
        WafField::Path,
    ];
    vec![
        WafRule::new(
            "preset-rce-shellshock",
            any_field_matches(&payload_and_headers, &re(SHELLSHOCK, ""), &[]),
            WafAction::Block,
        )
        .priority(40)
        .min_level(Low)
        .reason("Possible Shellshock (CVE-2014-6271) probe"),
        WafRule::new(
            "preset-rce-jndi",
            any_field_matches(
                &payload_and_headers,
                &re(JNDI_LOOKUP, "i"),
                &["${"],
            ),
            WafAction::Block,
        )
        .priority(40)
        .min_level(Low)
        .reason("Possible JNDI / Log4Shell lookup injection"),
        WafRule::new(
            "preset-rce-unix-cmd",
            any_field_matches(
                &payload_and_path,
                &re(UNIX_CMD_INJECTION, "i"),
                &[";", "`", "\n", "$(", "&&", "|"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Possible Unix command injection"),
        WafRule::new(
            "preset-rce-reverse-shell",
            any_field_matches(
                &payload_and_headers,
                &re(REVERSE_SHELL, "i"),
                &["/dev/", "nc", "sh", "socat", "mkfifo", "msfvenom"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Low)
        .reason("Possible reverse / bind shell payload"),
        WafRule::new(
            "preset-rce-download-exec",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(DOWNLOAD_EXEC, "i"),
                &[
                    "curl", "wget", "fetch", "base64", "python", "perl",
                    "ruby", "node", "php",
                ],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Low)
        .reason("Possible fetch-and-execute payload"),
        WafRule::new(
            "preset-rce-windows-lolbin",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(WINDOWS_LOLBIN, "i"),
                &[
                    "certutil",
                    "bitsadmin",
                    "mshta",
                    "regsvr32",
                    "wmic",
                    "msiexec",
                ],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Low)
        .reason("Possible Windows living-off-the-land binary abuse"),
        WafRule::new(
            "preset-rce-ssrf-metadata",
            any_field_matches(
                &payload_and_path,
                &re(SSRF_METADATA, "i"),
                &[
                    "169.254",
                    "metadata.google",
                    "100.100.100.200",
                    "192.0.0.192",
                    "instance-data",
                    "computemetadata",
                ],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Low)
        .reason("Possible SSRF to cloud instance metadata"),
        WafRule::new(
            "preset-rce-windows",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(WINDOWS_RCE, "i"),
                &["cmd", "powershell", "invoke-expression", "iex"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible Windows / PowerShell command injection"),
        WafRule::new(
            "preset-rce-ssti",
            any_field_matches(
                &payload_and_path,
                &re(SSTI, "i"),
                &["{{", "#{", "<%"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible server-side template injection"),
        WafRule::new(
            "preset-rce-freemarker",
            any_field_matches(
                &payload_and_path,
                &re(FREEMARKER, "i"),
                &["<#", "freemarker", "?new"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible FreeMarker template injection"),
        WafRule::new(
            "preset-rce-yaml-deserialization",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(YAML_UNSAFE_TAG, "i"),
                &["!!python", "!ruby/", "!!java", "!!javax"],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(Balanced)
        .reason(
            "Possible unsafe YAML deserialization (Python / Ruby / Java tag)",
        ),
        WafRule::new(
            "preset-rce-nodejs",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(NODE_RCE, "i"),
                &["child_process"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible Node.js child_process / require injection"),
        WafRule::new(
            "preset-rce-lang-exec",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(LANG_EXEC, "i"),
                &[
                    "system",
                    "popen",
                    "exec",
                    "subprocess",
                    "runtime",
                    "processbuilder",
                    "__import__",
                    "getoutput",
                ],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(Balanced)
        .reason("Possible process execution via language runtime API"),
        WafRule::new(
            "preset-rce-deserialization",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(DESERIALIZATION, "i"),
                &[
                    "ro0ab",
                    "aced0005",
                    "o:",
                    "a:",
                    "pickle",
                    "yaml",
                    "__reduce__",
                ],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(Balanced)
        .reason("Possible insecure deserialization payload"),
        WafRule::new(
            "preset-rce-shell-expression",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(SHELL_EXPANSION, ""),
                &["$(", "<(", "${"],
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason("Unix shell expression / substitution"),
        WafRule::new(
            "preset-rce-fork-bomb",
            any_field_matches(&PAYLOAD_FIELDS, &re(FORK_BOMB, ""), &[":("]),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason("Possible shell fork bomb"),
        WafRule::new(
            "preset-ssrf-internal",
            any_field_matches(
                &payload_and_path,
                &re(SSRF_INTERNAL, "i"),
                &["://"],
            ),
            WafAction::Block,
        )
        .priority(58)
        .min_level(Paranoid)
        .reason("Possible SSRF to a private / loopback host"),
        WafRule::new(
            "preset-rce-windows-cmd-set",
            any_field_matches(
                &payload_and_path,
                &re(WINDOWS_CMD_SET, "i"),
                &["set"],
            ),
            WafAction::Block,
        )
        .priority(58)
        .min_level(Paranoid)
        .reason("Possible cmd.exe injection via set /a or set /p"),
        WafRule::new(
            "preset-rce-asp-concat",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(ASP_STRING_CONCAT, "i"),
                &["\"&\"", "'&'", "\"+\"", "'+'"],
            ),
            WafAction::Block,
        )
        .priority(58)
        .min_level(Paranoid)
        .reason("Possible ASP / VBScript string-concatenation obfuscation"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `rce` preset.
pub fn rce_rules() -> &'static [WafRule] {
    &RULES
}
