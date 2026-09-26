# Benchmarks

What the engine costs per request. Regenerate with:

```sh
cargo run --release --example bench            # 20 000 iterations + 1 000 warmup
cargo run --release --example bench -- 100000
```

**Machine:** AMD Ryzen 7 5700X3D (16 threads), rustc 1.91.1, release profile. The cases mirror `A0`–`A6` of the TypeScript implementation's `npm run bench`, measured on the **same machine** (Node v24.15.0), so the two columns are directly comparable. Relative only — re-run locally before drawing conclusions about your hardware.

The harness (`examples/bench.rs`) builds each request once and clones it per iteration, so it measures `WafEngine::handle` only, not HTTP parsing or an adapter. `preset-dos-rate-limit` is disabled on `A1`–`A6` so repeated requests stay on the allow path.

## Results

p50 is the median of four runs; the range is the lowest and highest p50 of those runs. Run-to-run variance on this machine is up to ±10% — even `A0`, which evaluates no rule, moves by that much — so differences smaller than that are noise.

| ID | Case | Rules | p50 | p50 range | TypeScript p50 | Speed-up |
|---|---|---:|---:|---:|---:|---:|
| A0 | 0 rules (baseline `handle`) | 0 | 0.11 µs | 0.11–0.12 µs | 1.10 µs | 10× |
| A1 | `default` + `Balanced`, clean allow | 50 | 6.98 µs | 6.84–7.18 µs | 13.70 µs | 2.0× |
| A2 | A1 + decision cache (same fingerprint) | 50 | 0.69 µs | 0.67–0.69 µs | 2.00 µs | 2.9× |
| A3 | A1 + ~8 KB JSON body | 50 | 63.4 µs | 58.3–64.4 µs | 131.70 µs | 2.1× |
| A4 | A1 + small (~24 B) body | 50 | 7.97 µs | 7.81–8.17 µs | 14.40 µs | 1.8× |
| A5 | A1 SQLi — block path (early exit) | 50 | 5.05 µs | 4.90–5.13 µs | 8.60 µs | 1.7× |
| A6-low | `Low`, clean allow | 19 | 3.57 µs | 3.48–3.58 µs | 6.90 µs | 1.9× |
| A6-balanced | `Balanced`, clean allow | 50 | 6.96 µs | 6.84–7.06 µs | 13.30 µs | 1.9× |
| A6-high | `High`, clean allow (decoders on) | 80 | 12.4 µs | 11.84–12.92 µs | 28.10 µs | 2.3× |
| A6-paranoid | `Paranoid`, clean allow (decoders on) | 93 | 13.0 µs | 12.71–13.07 µs | 31.00 µs | 2.4× |

Latency is also far steadier: the TypeScript p95 on A1 is 31 µs (garbage collection and event-loop jitter), against 7–12 µs here.

## Where the time goes

- **Field resolution is indexed, not hashed.** Rules are compiled once so every distinct field gets a slot; per request each slot memoizes its values, lowercased values and decoded extras in a `OnceCell`. The first version keyed a `HashMap` by `Field` and handed out `Rc`s, and ran A1 at 13.5 µs — the same as TypeScript. Slots halved it.
- **A regex call on a short value costs ~12 ns**, so clean small requests are dominated by the number of leaf conditions, not by pattern complexity.
- **Large bodies are bounded by regex throughput.** Rules without a `requires` prefilter scan the whole value; the lazy DFA runs at roughly 0.5 GB/s on case-insensitive alternations, ~17 µs per rule on 8 KB. Rules **with** `requires` skip a body that contains none of their literals after a substring search.
- **Literal budget.** The `regex` crate accelerates a pattern with a literal prefilter only while the (case-expanded) literal set stays small. `preset-rce-deserialization` has seven case-insensitive arms; together they exceeded that budget and took ~135 µs on a clean 8 KB body, versus ~1 µs for any six of them. A complete `requires` list restored it (A3: 193 µs → 58 µs) without changing what the rule detects. Watch for this when writing wide case-insensitive alternations: measure, and add `requires`.
- **JavaScript whitespace.** Rules see `\s` the JavaScript way (NBSP, `U+2000`–`U+200A`, `U+3000`, … count as whitespace). Rewriting the patterns to say so defeated the literal prefilters (`preset-xss-body` went from 0.6 µs to 17 µs on 8 KB), so the *value* is mapped instead: one memoized `is_ascii` scan per field, and a mapped copy only for values that contain such a space. Measured head-to-head it costs about 0.2–0.3 µs on A1.
- **Transport decoding** (`High`+) costs a memoized shape check per field on clean traffic: a Base64 byte-class test, a `%` search and a `/*` search. It is zero at `Low` / `Balanced`. A raw body is also split once into its JSON string values, form values or multipart fields for the decoders: ≈ +2 % on an ~8 KB form body, ≈ +3 % on a multipart one, nothing on text or JSON. The raw JSON body is still scanned as sent; each JSON string written with `\uXXXX` or `\/` escapes is also scanned decoded, up to 16 per body: ≈ +3 % on a 6 KB body with one such string, ≈ +24 % when every string is escaped.
