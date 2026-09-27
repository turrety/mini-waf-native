# Benchmarks

What the engine costs per request. Regenerate with:

```sh
cargo run --release --example bench            # 20 000 iterations + 10 000 warmup
cargo run --release --example bench -- 100000
```

**Machine:** AMD Ryzen 7 5700X3D (16 threads), rustc 1.91.1, release profile. The cases mirror `A0`–`A6` of the TypeScript implementation's `npm run bench`, measured on the **same machine** (Node v24.15.0), so the two columns are directly comparable. Relative only — re-run locally before drawing conclusions about your hardware.

The harness (`rust/examples/bench.rs`) builds each request once and clones it per iteration, so it measures `WafEngine::handle` only, not HTTP parsing or an adapter. `preset-dos-rate-limit` is disabled on `A1`–`A6` so repeated requests stay on the allow path.

## Results

p50 is the median of four runs; the range is the lowest and highest p50 of those runs. Run-to-run variance on this machine is up to ±10%, so differences smaller than that are noise.

| ID | Case | Rules | p50 | p50 range | TypeScript p50 | Speed-up |
|---|---|---:|---:|---:|---:|---:|
| A0 | 0 rules (baseline `handle`) | 0 | 0.10 µs | 0.10–0.10 µs | 1.10 µs | 11× |
| A1 | `default` + `Balanced`, clean allow | 50 | 7.00 µs | 6.94–7.01 µs | 13.70 µs | 2.0× |
| A2 | A1 + decision cache (same fingerprint) | 50 | 0.62 µs | 0.61–0.64 µs | 2.00 µs | 3.2× |
| A3 | A1 + ~8 KB JSON body | 50 | 58.3 µs | 58.3–58.3 µs | 131.70 µs | 2.3× |
| A4 | A1 + small (~24 B) body | 50 | 8.06 µs | 7.93–8.23 µs | 14.40 µs | 1.8× |
| A5 | A1 SQLi — block path (early exit) | 50 | 5.07 µs | 5.04–5.24 µs | 8.60 µs | 1.7× |
| A6-low | `Low`, clean allow | 19 | 3.51 µs | 3.51–3.58 µs | 6.90 µs | 2.0× |
| A6-balanced | `Balanced`, clean allow | 50 | 6.97 µs | 6.93–7.01 µs | 13.30 µs | 1.9× |
| A6-high | `High`, clean allow (decoders on) | 80 | 12.2 µs | 11.7–12.7 µs | 28.10 µs | 2.3× |
| A6-paranoid | `Paranoid`, clean allow (decoders on) | 93 | 12.8 µs | 12.6–13.6 µs | 31.00 µs | 2.4× |

Latency is also far steadier: the TypeScript p95 on A1 is 31 µs (garbage collection and event-loop jitter), against about 7 µs here.

## Bindings

The C, C++, Java and .NET bindings each ship the same A0–A6 harness. Unlike `rust/examples/bench.rs`, which implements `WafHttpContext` directly, they go through `create_adapter` and `protect`, the way a server uses them, so their numbers include the adapter and every callback across the C ABI. Same machine, 20 000 iterations + 10 000 warmup, p50 as the median of four runs:

```sh
cargo build --release -p mini-waf-ffi
cmake -S c -B target/c -DCMAKE_BUILD_TYPE=Release && cmake --build target/c && target/c/bench
cmake -S cpp -B target/cpp -DCMAKE_BUILD_TYPE=Release && cmake --build target/cpp && target/cpp/bench
cd java && mvn -B -q compile && java --enable-native-access=ALL-UNNAMED -cp target/classes \
    -Dmini_waf.library.path=../target/release examples/Bench.java
cd dotnet && MINI_WAF_LIBRARY_PATH=$PWD/../target/release dotnet run -c Release --project MiniWaf.Bench
```

| ID | Rust (`handle`) | C | C++ | Java 22 | .NET 8 |
|---|---:|---:|---:|---:|---:|
| A0 | 0.10 µs | 0.21 µs | 0.22 µs | 2.27 µs | 0.60 µs |
| A1 | 7.00 µs | 7.83 µs | 8.27 µs | 9.52 µs | 9.75 µs |
| A2 | 0.62 µs | 1.61 µs | 1.97 µs | 3.12 µs | 3.60 µs |
| A3 | 58.3 µs | 65.0 µs | 65.6 µs | 67.8 µs | 68.6 µs |
| A4 | 8.06 µs | 8.78 µs | 9.09 µs | 10.4 µs | 11.1 µs |
| A5 | 5.07 µs | 5.83 µs | 6.22 µs | 7.53 µs | 7.85 µs |
| A6-low | 3.51 µs | 4.29 µs | 4.64 µs | 5.62 µs | 6.10 µs |
| A6-balanced | 6.97 µs | 7.87 µs | 8.31 µs | 9.45 µs | 9.75 µs |
| A6-high | 12.2 µs | 13.0 µs | 13.6 µs | 15.1 µs | 16.2 µs |
| A6-paranoid | 12.8 µs | 14.1 µs | 14.8 µs | 16.1 µs | 17.2 µs |

- The adapter and callbacks add about 0.8 µs (C) to 2.8 µs (.NET) to a clean request, and 7–10 µs to the 8 KB body. Whenever rules are evaluated (A1, A3–A6) every binding is 1.1–2.2× faster than the TypeScript engine. When almost nothing is evaluated (A0, and A2, a cache hit) the fixed cost of the call dominates, and there Java and .NET are slower than TypeScript.
- The JVM's A0 moves between 0.9 and 2.7 µs from run to run; the other Java rows are stable within ±3 %.
- The .NET harness turns tiered compilation off (`MiniWaf.Bench.csproj`) so every case runs fully optimized code; with it on, A1 still ran at the first tier (13.9 µs against 9.9 µs for the identical A6-balanced). `Stopwatch` resolves 0.1 µs on this machine, hence the round .NET figures.

## Detection (GoTestWAF)

[GoTestWAF](https://github.com/wallarm/gotestwaf) was run against a small echo server per stack, each handing the WAF the raw request (method, raw target, peer IP, headers, raw body bytes): axum for Rust, mongoose for C, cpp-httplib for C++, the JDK `HttpServer` for Java and Kestrel for .NET. Configuration: `default` preset at `High` with `preset-protocol-host-ip` off; the `inj` profile also turns off the rate limit and the scanner user-agent rules, which otherwise block every GoTestWAF request (true negatives included). Block = 403, pass = 200/404, `--workers=5 --sendDelay=50 --randomDelay=50`.

| Stack | `inj` score | Attacks blocked | False positives | `high` score |
|---|---:|---:|---:|---:|
| TypeScript (Express, parsed bodies) | 90.28 | 549/668 | 6/141 | 73.44 |
| Rust | 90.17 | 560/675 | 11/141 | 73.45 |
| C | 90.23 | 560/673 | 11/141 | 73.44 |
| C++ | 89.16 | 508/653 | 6/141 | 74.11 |
| Java | 90.19 | 555/668 | 11/140 | 73.43 |
| .NET | 90.17 | 559/674 | 11/141 | 73.45 |

The engine is the same everywhere: fed the same bytes, Rust and TypeScript return the same decision and the same rule id (a differential check over 1 249 raw bodies, plus every row that differed here, replayed on its own). The rows differ because each server hands the WAF something different, or answers before the WAF runs:

- **TypeScript / Express** hands the engine the *parsed* body re-serialized as JSON, not the bytes on the wire. The app sees `\r\n`, quotes and `+` exactly as the parsers decoded them, so a payload the parsers neutralize is not an attack on that app. Express also answers 7 malformed requests itself (400 from body-parser, 500 from multer).
- **Rust, C, Java, .NET** hand the raw body. Multipart framing puts a line break right before each field value, which is why benign texts that start with a command word (`ls 300 lexus`) count as 5 extra false positives.
- **C (mongoose)** and **Java (JDK `HttpServer`)** drop a few connections under GoTestWAF's concurrency (2–12 rows, different on every run); replayed one by one they match Rust.
- **.NET (Kestrel)** rejects a `%00` in the path with 400 before the app.
- **C++ (cpp-httplib)** answers 22 requests itself (413 on form bodies over 8 KB, 400/415 on malformed ones) and pre-parses multipart bodies, so its target passes the WAF rebuilt `name=content` lines instead of the raw body.

The `high` score is low for every stack by design: GoTestWAF's own user agent and request rate trip the scanner and rate-limit rules, which also makes that profile timing-dependent row by row.

## Where the time goes

- **Field resolution is indexed, not hashed.** Rules are compiled once so every distinct field gets a slot; per request each slot memoizes its values, lowercased values and decoded extras in a `OnceCell`. The first version keyed a `HashMap` by `Field` and handed out `Rc`s, and ran A1 at 13.5 µs — the same as TypeScript. Slots halved it.
- **A regex call on a short value costs ~12 ns**, so clean small requests are dominated by the number of leaf conditions, not by pattern complexity.
- **Large bodies are bounded by regex throughput.** Rules without a `requires` prefilter scan the whole value; the lazy DFA runs at roughly 0.5 GB/s on case-insensitive alternations, ~17 µs per rule on 8 KB. Rules **with** `requires` skip a body that contains none of their literals after a substring search.
- **Literal budget.** The `regex` crate accelerates a pattern with a literal prefilter only while the (case-expanded) literal set stays small. `preset-rce-deserialization` has seven case-insensitive arms; together they exceeded that budget and took ~135 µs on a clean 8 KB body, versus ~1 µs for any six of them. A complete `requires` list restored it (A3: 193 µs → 58 µs) without changing what the rule detects. Watch for this when writing wide case-insensitive alternations: measure, and add `requires`.
- **JavaScript whitespace.** Rules see `\s` the JavaScript way (NBSP, `U+2000`–`U+200A`, `U+3000`, … count as whitespace). Rewriting the patterns to say so defeated the literal prefilters (`preset-xss-body` went from 0.6 µs to 17 µs on 8 KB), so the *value* is mapped instead: one memoized `is_ascii` scan per field, and a mapped copy only for values that contain such a space. Measured head-to-head it costs about 0.2–0.3 µs on A1.
- **Transport decoding** (`High`+) costs a memoized shape check per field on clean traffic: a Base64 byte-class test, a `%` search and a `/*` search. It is zero at `Low` / `Balanced`. A raw body is also split once into its JSON string values, form values or multipart fields for the decoders: ≈ +2 % on an ~8 KB form body, ≈ +3 % on a multipart one, nothing on text or JSON. The raw JSON body is still scanned as sent; each JSON string written with `\uXXXX` or `\/` escapes is also scanned decoded, up to 16 per body: ≈ +3 % on a 6 KB body with one such string, ≈ +24 % when every string is escaped.
