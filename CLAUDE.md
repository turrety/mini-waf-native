# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Layout

One folder per language: `rust/` (the `mini-waf` crate: `src/`, `tests/`, `examples/`), `rust-ffi/` (its C ABI), and the `c/`, `cpp/`, `java/` and `dotnet/` bindings. The root `Cargo.toml` is a virtual workspace over `rust` and `rust-ffi`, so `Cargo.lock` and `target/` stay at the root; run every `cargo` command from there.

## Commands

```bash
cargo test --workspace                      # unit + integration + doc tests (README snippets included)
cargo test --test presets                   # attack / benign corpus only
cargo test -- rate_limits                   # filter by test name
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --check                  # rustfmt.toml: 80 columns, vertical imports (nightly-only options)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo run --release --example bench         # engine benchmarks (see BENCHMARKS.md)
cargo run --example std_server              # dependency-free demo server on :8080
```

## What this is

A Rust rewrite of the TypeScript `mini-waf` (sibling repo `../mini-waf-ts`) with **the same public API**. Rule ids, levels, preset behaviour and decisions match it; the TS test corpus was ported to `rust/tests/presets.rs`. Framework plugins were intentionally **not** ported: `create_adapter` is the only integration point.

## API parity with TypeScript

Every name exported by `mini-waf-ts/src/index.ts` exists at the crate root, mapped mechanically. Like `index.ts`, `rust/src/lib.rs` glob re-exports each folder's barrel (`mod.rs` = `index.ts`, with explicit `pub use` lists); modules themselves are private. The mapping:

- `camelCase` functions / methods / fields / handler names → `snake_case` (`createMiniWaf` → `create_mini_waf`, `getRawBody` → `get_raw_body`, `windowMs` → `window_ms`); type names unchanged (`WafRule`, `WafHttpContext`, `CustomAdapterHandlers`, …).
- String unions → enums (`WafAction`, `ProtectionLevel`, `WafPresetName`, `WafField`, `WafLogLevel`).
- Optional properties / parameters → `Option` (`WafConfig` fields, `WafRule::priority`, `create_mini_waf(config, None)`, `now: Option<i64>`).
- Exported values → zero-argument functions of the same name (`default_rules()`, `silent_logger()`).
- JSON rule keys stay camelCase, so one rules file loads in both.

Only absent: the Express/Fastify/Nest plugins and adapters, and `scanRulesAsync` / `ruleYieldEvery` (no event loop). When adding or renaming anything public, follow the same mapping and keep the README sections "Coming from TypeScript" and "Differences from the TypeScript version" true.

## Architecture

The folder and file layout mirrors `mini-waf-ts/src` one to one (`kebab-case.ts` → `snake_case.rs`, `index.ts` → `mod.rs`); keep it that way when adding files:

- `domain/` — `rules.rs` (as in `rules.ts`: `MatchPattern` / `MatchPredicate`, `WafField`, `FieldCondition`, `WafCondition` and its variants, `WafRule`, `WafPresetName`, `WafConfig`, `WafEvaluationResult`, type guards), `context.rs` (`WafHttpContext`, `WafAdapter`, block defaults), `values.rs` (JSON model, headers, query, cookies, uploads), `serializable.rs` (`JsonWafRule` …), `levels.rs`.
- `adapters/create_adapter.rs` — `CustomAdapterHandlers` + `create_adapter` → `CustomAdapter` (a `WafAdapter` whose context caches values in `OnceCell`s).
- `engine/` — `mod.rs` (`create_mini_waf`, `MiniWafInstance` = `WafEngine` + `protect`, `run_with_adapter`), `engine.rs` (`create_waf_engine`, `build_rule_list`, `scan_rules`, `handle`, decision cache), `evaluate.rs` (compiles conditions into `Program` trees whose leaves point at field **slots**; `evaluate_condition`), `field_resolver.rs` (per-request slot memo; standalone `resolve_field_*`), `matcher.rs` (`matches_pattern`, `compile_regex`, `js_regex_view`), `normalize_condition.rs`, `condition_utils.rs`, `rule_filter.rs`, `decode.rs`, `rate_limit.rs`, `fingerprint.rs`, `load_rules.rs`.
- `presets/` — one file per pack, each owning its `LazyLock` and `*_rules()`; `fields.rs` has the field groups, `re()`, `any_field_matches()` and `preset()`; `default.rs` concatenates the packs; `mod.rs` has `resolve_presets`.
- `logging/` — `port.rs` (`WafLogger`, levels, `resolve_logging`) and `logger.rs` (console logger).
- `utils/` — `cookies.rs`, `ip.rs`, `lru.rs` as in TS, plus the Rust-only pieces TS gets from the platform: `json.rs` (parser / serializer), `encoding.rs`, `time.rs`, `ordered_map.rs`. The only dependency is `regex`; keep it that way.

Every field is read through `WafHttpContext`, so an adapter returning the wrong `get_ip()` silently breaks every `ip` rule and rate-limit bucket.

## Invariants (measured — see BENCHMARKS.md)

- Field lookups go through compiled slot indices; do not reintroduce per-leaf hashing of `WafField`.
- Regexes run over bytes with Unicode **off** by default (JS semantics, small automata). No look-around/backrefs exist in the dialect; emulate in code (see `presets/rfi.rs` `has_external_doctype`, `engine/decode.rs` comment stripping).
- JavaScript's `\s` matches Unicode spaces even without `u`. That is handled by matching regexes against `js_regex_view(value)` (memoized per slot), **not** by rewriting patterns: rewriting `\s` blew the literal prefilter budget (`preset-xss-body` 0.6 → 17 µs on 8 KB). Predicates get the raw value; a predicate that runs regexes must apply the view itself (see the XXE predicate).
- Wide case-insensitive alternations can exceed the `regex` literal budget and lose their prefilter (`preset-rce-deserialization` went 1 µs → 135 µs on 8 KB). Measure new presets on an 8 KB body; add a **complete** `requires` list.
- `requires` must list a literal that *every* match contains, or the rule silently stops detecting.

## Presets

Rule ids are public API and `rust/tests/presets.rs` asserts which id fires for each attack. The benign corpus there must stay `allow` at `High`/`Paranoid`; a new rule that blocks any of it is a false positive.

## Conventions

- Code, comments, docs and commits in English; Conventional Commits (`feat(engine):`, `fix(presets):`, `docs:`).
- No `unsafe` in the crate; `rust-ffi/` is the only `unsafe` code, and every block there carries a `// SAFETY:` comment. Prefer immutable transforms; local `mut` accumulators in hot loops are fine.
- Imports are crate-absolute (`use crate::engine::matcher::…`), like the TS `@/` alias; `use super::*` only in test modules. rustfmt lays them out: one `use` per module, one item per line, grouped std / external / crate.
- Keep functions small and named after their step (see `build_rules`, `IndexScan::record_match`, the `Node` reader in `load_rules.rs`); descriptive closure parameters, no single letters. No section-banner comments.
- Format with **nightly** rustfmt (`cargo +nightly fmt`): `rustfmt.toml` sets 80 columns, vertical imports, comment wrapping and doc-comment code formatting, which are unstable options. Stable `cargo fmt` ignores them and undoes the import layout. rustfmt cannot split string literals or README snippets: break long regexes and strings with `concat!`, and keep README code blocks within 80 columns by hand.
- Unit tests live next to the code in `#[cfg(test)] mod tests` (they can reach private items); `rust/tests/` holds integration tests that use only the public API, as the Rust book recommends.
- README Rust blocks are doc-tested (`ReadmeDoctests` in `lib.rs`); mark snippets needing external crates `rust,ignore` and verify them separately.

## Bindings

`c/`, `cpp/`, `java/` and `dotnet/` hold the bindings (build and test commands in `BINDINGS.md`). They all sit on `rust-ffi/` (`mini-waf-ffi`, lib name `mini_waf`, `cdylib` + `staticlib`, no rlib or docs so it does not collide with the crate). It exports the C ABI declared in `c/include/mini_waf.h`; C++, Java and .NET all go through it.

- Names are the Rust ones, recased only: `mini_waf_` + Rust path in C (`mini_waf_waf_rule_reason`, fields as `_get_<field>`), `requires_any` / `not_` in C++ (keywords; the user rejects trailing underscores on new names), `WafField.QueryParam` in C# (clashes with the `Query` field). The user rejected renamed concepts (`WafRequest` for `WafHttpContext`); do not introduce any.
- Adding or changing an export means updating, in the same change: `mini_waf.h` (`rust-ffi/tests/header.rs` fails when it drifts from the exports), `java/.../Api.java`, `dotnet/MiniWaf/Api.cs`, then the wrappers and tests of all four languages. `Api.java` and `Api.cs` are generated from the header's declarations by the gitignored `toolchains-lab/gen/` scripts (`regen_check.py write`, `regen_cs.py <out>`); regenerate rather than hand-edit, then run CSharpier.
- Loggers and shared rate-limit stores cross the ABI as `WafEngineOptions`. A logger callback gets the request as a `WafHttpContextRef` (the borrowed `&dyn WafHttpContext`); the wrappers turn it into a read-only `WafHttpContext` and route logger exceptions through the same per-thread frame as the other callbacks. Never add engine features just to serve one binding: the user rejected that (the discarded TypeScript binding).
- Callbacks never unwind through Rust: the wrappers park a thrown exception in a per-thread frame and rethrow after the native call returns. `catch_unwind` guards the Rust side.
- `libmini_waf` is loaded from `target/release` by default (CMake `MINI_WAF_LIBRARY_DIR`, Maven `mini-waf.library.dir`, `MINI_WAF_LIBRARY_PATH` for Java/.NET). Rebuild it (`cargo build --release -p mini-waf-ffi`) before running the Java/.NET tests, or they fail with a missing symbol.
- 80 columns everywhere, enforced by CI: clang-format for C/C++ (one `.clang-format` per folder: `char *p` in C, `char* p` in C++), Checkstyle for Java (a check only, no formatter), CSharpier for C#. None of them wraps comments; `toolchains-lab/gen/wrap_comments.py` does. Commands are in `BINDINGS.md`.
- Local toolchains (JDK, Maven, .NET SDK, clang-format) live in the gitignored `toolchains-lab/`; CI installs its own.
- CI is one workflow per stack (`.github/workflows/{rust,c,cpp,java,dotnet}.yml`), each running that stack's tests on Linux, Windows and macOS (x64 and arm64) plus its format check; Rust, C and C++ also test 32-bit x86. Code must stay free of anything specific to an OS or architecture. A binding's workflow also runs when `rust/`, `rust-ffi/` or `Cargo.*` change, since it tests against a fresh `libmini_waf`.
- C++ tests are Catch2 v3 BDD scenarios (`SCENARIO` / `GIVEN` / `WHEN` / `THEN`), fetched by CMake `FetchContent`. Each binding has an A0–A6 bench (`c/examples/bench.c`, `cpp/examples/bench.cpp`, `java/examples/Bench.java`, `dotnet/MiniWaf.Bench`) that goes through `protect`; results in `BENCHMARKS.md`.
