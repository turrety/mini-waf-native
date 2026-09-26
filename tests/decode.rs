//! The transport decoders end to end: Base64, percent-encoding and inline SQL
//! comments are off at `balanced`, on at `high`, and overridable either way.

mod common;

use common::{
    MockRequest,
    b64,
    full_encode,
};
use mini_waf::ProtectionLevel::{
    Balanced,
    High,
};
use mini_waf::{
    DecodeConfig,
    MiniWafInstance,
    ProtectionLevel,
    WafConfig,
    WafDecision,
    WafPresetName,
    create_mini_waf,
};

fn engine(level: ProtectionLevel, decode: DecodeConfig) -> MiniWafInstance {
    create_mini_waf(
        WafConfig::default()
            .presets([WafPresetName::Default])
            .level(level)
            .decode(decode),
        None,
    )
}

fn blocked_by_sqli(waf: &MiniWafInstance, req: MockRequest) -> bool {
    let result = waf.handle(&mut { req });
    result.decision == WafDecision::Block
        && result
            .matched_rule
            .map(|rule| rule.id.as_str())
            .is_some_and(|id| id.starts_with("preset-sqli"))
}

fn is_blocked(waf: &MiniWafInstance, req: MockRequest) -> bool {
    waf.handle(&mut { req }).decision == WafDecision::Block
}

const NONE: DecodeConfig = DecodeConfig {
    base64: None,
    url: None,
    comments: None,
};

mod base64 {
    use super::*;

    fn blob() -> String {
        b64("1 UNION SELECT username, password FROM users")
    }

    #[test]
    fn is_off_at_balanced() {
        assert!(!is_blocked(
            &engine(Balanced, NONE),
            MockRequest::new().query("q", blob())
        ));
    }

    #[test]
    fn auto_decodes_at_high() {
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().query("q", blob())
        ));
    }

    #[test]
    fn can_be_forced_on_or_off() {
        let on = DecodeConfig {
            base64: Some(true),
            ..NONE
        };
        let off = DecodeConfig {
            base64: Some(false),
            ..NONE
        };
        assert!(is_blocked(
            &engine(Balanced, on),
            MockRequest::new().query("q", blob())
        ));
        assert!(!is_blocked(
            &engine(High, off),
            MockRequest::new().query("q", blob())
        ));
    }

    #[test]
    fn reaches_json_body_values() {
        let body = format!(r#"{{"q":"{}"}}"#, blob());
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
        assert!(!is_blocked(
            &engine(Balanced, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
        let nested = format!(
            r#"{{"outer":{{"list":["{}"]}}}}"#,
            b64("<body onload=alert(document.cookie)>")
        );
        assert!(is_blocked(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(&nested)
        ));
    }

    #[test]
    fn ignores_benign_json_values() {
        let body = format!(
            concat!(
                r#"{{"sessionId":"{}","note":"{}","#,
                r#""avatarHash":"550e8400e29b41d4a716446655440000"}}"#,
            ),
            b64("sid=8f3a2b1c9d0e4f5a6b7c8d9e0f1a2b3c"),
            b64("the quarterly report is attached to this thread")
        );
        assert!(!is_blocked(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
    }

    #[test]
    fn reaches_raw_form_body_values() {
        let body = format!("name=alice&q={}", blob());
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
        assert!(!is_blocked(
            &engine(Balanced, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
    }

    #[test]
    fn reaches_raw_multipart_fields() {
        let body = format!(
            concat!(
                "--boundary42\r\n",
                "Content-Disposition: form-data; name=\"q\"\r\n\r\n",
                "{}\r\n",
                "--boundary42--\r\n",
            ),
            blob()
        );
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(&body)
        ));
    }

    #[test]
    fn reaches_path_segments() {
        let path = format!("/download/{}", b64("<body onload=alert('test1')>"));
        assert!(is_blocked(
            &engine(High, NONE),
            MockRequest::new().path(&path)
        ));
    }
}

mod url {
    use super::*;

    fn encoded() -> String {
        full_encode("1 UNION SELECT username, password FROM users")
    }

    #[test]
    fn is_off_at_balanced() {
        assert!(!is_blocked(
            &engine(Balanced, NONE),
            MockRequest::new().query("q", encoded())
        ));
    }

    #[test]
    fn auto_decodes_at_high() {
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().query("q", encoded())
        ));
    }

    #[test]
    fn can_be_forced_on_or_off() {
        let on = DecodeConfig {
            url: Some(true),
            ..NONE
        };
        let off = DecodeConfig {
            url: Some(false),
            ..NONE
        };
        assert!(is_blocked(
            &engine(Balanced, on),
            MockRequest::new().query("q", encoded())
        ));
        assert!(!is_blocked(
            &engine(High, off),
            MockRequest::new().query("q", encoded())
        ));
    }

    #[test]
    fn decodes_a_traversal_on_the_path() {
        let path = format!("/download/{}", full_encode("../../../etc/passwd"));
        assert!(is_blocked(
            &engine(High, NONE),
            MockRequest::new().path(&path)
        ));
    }

    #[test]
    fn scans_the_raw_json_body_alongside_its_decoded_strings() {
        // The decoded strings are extra candidates: the raw body is still
        // scanned, so `\u003c<tag>` stays visible at `High`.
        let body = r#"{"q": "\u003ciframe src=//evil.example\u003e"}"#;
        for level in [Balanced, High] {
            let waf = engine(level, NONE);
            let result =
                waf.handle(&mut MockRequest::new().method("POST").body(body));
            assert_eq!(
                result.matched_rule.map(|rule| rule.id.as_str()),
                Some("preset-xss-encoded-tag")
            );
        }
    }

    #[test]
    fn resolves_json_escapes_in_a_raw_body() {
        // What a JSON parser hands the framework: `1 union select ...`.
        let body = concat!(
            r#"{"test": true, "q": "1\u0020union\u0020select"#,
            r#"\u0020password\u0020from\u0020users"}"#,
        );
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().method("POST").body(body)
        ));
        let off = DecodeConfig {
            url: Some(false),
            ..NONE
        };
        assert!(!is_blocked(
            &engine(High, off),
            MockRequest::new().method("POST").body(body)
        ));
    }
}

mod comments {
    use super::*;

    const TAMPERED: &str =
        "1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users";

    #[test]
    fn is_off_at_balanced() {
        assert!(!is_blocked(
            &engine(Balanced, NONE),
            MockRequest::new().query("q", TAMPERED)
        ));
    }

    #[test]
    fn auto_strips_at_high() {
        assert!(blocked_by_sqli(
            &engine(High, NONE),
            MockRequest::new().query("q", TAMPERED)
        ));
    }

    #[test]
    fn can_be_forced_on_or_off() {
        let on = DecodeConfig {
            comments: Some(true),
            ..NONE
        };
        let off = DecodeConfig {
            comments: Some(false),
            ..NONE
        };
        assert!(is_blocked(
            &engine(Balanced, on),
            MockRequest::new().query("q", TAMPERED)
        ));
        assert!(!is_blocked(
            &engine(High, off),
            MockRequest::new().query("q", TAMPERED)
        ));
    }

    #[test]
    fn strips_comments_on_the_path() {
        let req = MockRequest::new()
            .path("/report/1/**/UNION/**/SELECT/**/pass/**/FROM/**/users");
        assert!(is_blocked(&engine(High, NONE), req));
    }
}
