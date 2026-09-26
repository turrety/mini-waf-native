//! The C header declares exactly the functions the library exports.

use std::collections::BTreeSet;
use std::fs;

/// `text` without its `/* ... */` comments.
fn strip_comments(text: &str) -> String {
    text.split("/*")
        .enumerate()
        .map(|(index, chunk)| match index {
            0 => chunk,
            _ => chunk.split_once("*/").map_or("", |(_, code)| code),
        })
        .collect()
}

/// Every `mini_waf_*` identifier directly followed by `suffix`.
fn names_before(source: &str, suffix: &str) -> BTreeSet<String> {
    source
        .match_indices("mini_waf_")
        .map(|(start, _)| {
            let rest = &source[start..];
            let end = rest
                .find(|char: char| !char.is_ascii_alphanumeric() && char != '_')
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        })
        .filter(|(_, after)| after.starts_with(suffix))
        .map(|(name, _)| name.to_owned())
        .collect()
}

#[test]
fn header_matches_exports() {
    let root = env!("CARGO_MANIFEST_DIR");
    let header =
        fs::read_to_string(format!("{root}/../c/include/mini_waf.h")).unwrap();
    let declared = names_before(&strip_comments(&header), "(");

    let exported: BTreeSet<String> = fs::read_dir(format!("{root}/src"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .flat_map(|source| {
            let functions = names_before(&source, "(");
            let macro_setters = names_before(&source, " =>");
            functions.into_iter().chain(macro_setters)
        })
        .filter(|name| name != "mini_waf_")
        .collect();

    assert!(exported.len() > 90, "found {} exports", exported.len());
    assert_eq!(declared, exported);
}
