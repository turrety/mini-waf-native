# mini-waf bindings

C, C++, Java and .NET bindings of the `mini-waf` crate. All four sit on
one C ABI, `libmini_waf`, built from `rust-ffi/`. Each binding keeps
the Rust names and changes only their casing, so the crate docs and the
main README apply to every language.

| Folder      | Language             | Built with | Requires         |
| ----------- | -------------------- | ---------- | ---------------- |
| `rust-ffi/` | Rust (`cdylib`)      | Cargo      | Rust 1.85        |
| `c/`        | C11                  | CMake      | a C11 compiler   |
| `cpp/`      | C++17, header-only   | CMake      | a C++17 compiler |
| `java/`     | Java (FFM API)       | Maven      | JDK 22+          |
| `dotnet/`   | C# (`LibraryImport`) | .NET SDK   | .NET 8+          |

## Building the library

```bash
cargo build --release -p mini-waf-ffi
```

This writes `target/release/libmini_waf.so` (`.dylib` on macOS,
`mini_waf.dll` on Windows) and the static `libmini_waf.a`. Every binding
looks for the library in `target/release` by default.

## C

The API is `c/include/mini_waf.h`. The header starts with its
conventions: ownership, text, optional values and callbacks.

```bash
cmake -S c -B target/c && cmake --build target/c
ctest --test-dir target/c --output-on-failure
target/c/protect
```

The CMake project exports the imported target `mini_waf::mini_waf`. Set
`MINI_WAF_LIBRARY_DIR` to link against a library built somewhere else.

## C++

`cpp/include/mini_waf.hpp` is a header-only wrapper over `mini_waf.h`.
Ownership is RAII and errors are exceptions.

```bash
cmake -S cpp -B target/cpp && cmake --build target/cpp
ctest --test-dir target/cpp --output-on-failure
target/cpp/protect
```

The tests are Catch2 v3 BDD scenarios (`SCENARIO` / `GIVEN` / `WHEN` /
`THEN`). CMake fetches Catch2 on the first configure, so that step needs
network access; the header itself has no dependency.

```cpp
auto waf = mini_waf::create_mini_waf(
    mini_waf::WafConfig()
        .presets({mini_waf::WafPresetName::Default})
        .level(mini_waf::ProtectionLevel::Balanced));
```

## Java

This binding uses the Foreign Function & Memory API. The package is
`io.github.murylloex.miniwaf`, and the crate's free functions are static
methods of `MiniWaf`.

```bash
cd java
mvn -B test
```

The library is loaded from the directory named by the
`mini_waf.library.path` system property, then by the
`MINI_WAF_LIBRARY_PATH` environment variable, then from the system library
path. Run with `--enable-native-access=ALL-UNNAMED` so the JVM does not
warn about native access. `examples/Protect.java` shows how to run the
example.

```java
MiniWafInstance waf = MiniWaf.createMiniWaf(new WafConfig()
    .presets(WafPresetName.DEFAULT)
    .level(ProtectionLevel.BALANCED));
```

## .NET

The namespace and package are `MurylloEx.MiniWaf`. The crate's free
functions are static methods of `MiniWaf`.

```bash
cd dotnet
dotnet test
MINI_WAF_LIBRARY_PATH=$PWD/../target/release \
    dotnet run --project MiniWaf.Example
```

The library is loaded from the directory named by
`MINI_WAF_LIBRARY_PATH`, then through the default probing: the
application directory, then `LD_LIBRARY_PATH` / `PATH`. The test project
finds `target/release` on its own.

```csharp
using MiniWafInstance waf = MiniWaf.CreateMiniWaf(new WafConfig()
    .Presets(WafPresetName.Default)
    .Level(ProtectionLevel.Balanced));
```

## Benchmarks

Every binding has an A0–A6 harness that mirrors `examples/bench.rs` and
goes through `create_adapter` / `protect`: `c/examples/bench.c`,
`cpp/examples/bench.cpp`, `java/examples/Bench.java` and
`dotnet/MiniWaf.Bench`. Build C and C++ with
`-DCMAKE_BUILD_TYPE=Release`. The commands and the results are in
[`BENCHMARKS.md`](BENCHMARKS.md#bindings).

## Names

Rust names are only recased:

| Rust                            | C                                            | C++                           | Java                      | .NET                      |
| ------------------------------- | -------------------------------------------- | ----------------------------- | ------------------------- | ------------------------- |
| `create_mini_waf`               | `mini_waf_create_mini_waf`                   | `create_mini_waf`             | `MiniWaf.createMiniWaf`   | `MiniWaf.CreateMiniWaf`   |
| `MiniWafInstance::protect`      | `mini_waf_mini_waf_instance_protect`         | `MiniWafInstance::protect`    | `protect`                 | `Protect`                 |
| `WafRule::reason` (builder)     | `mini_waf_waf_rule_reason`                   | `reason`                      | `reason`                  | `Reason`                  |
| `rule.id` (field)               | `mini_waf_waf_rule_get_id`                   | `id()`                        | `id()`                    | `Id()`                    |
| `WafField::Ip`                  | `mini_waf_waf_field_from_str("ip")`          | `WafField::Ip()`              | `WafField.IP`             | `WafField.Ip`             |
| `WafField::Query(name)`         | `mini_waf_waf_field_query`                   | `WafField::query`             | `WafField.query`          | `WafField.QueryParam`     |
| `FieldCondition::requires`      | `mini_waf_field_condition_requires`          | `requires_any`                | `requires`                | `Requires`                |
| `WafCondition::Not`             | `mini_waf_waf_condition_not`                 | `WafCondition::not_`          | `WafCondition.not`        | `WafCondition.Not`        |
| `ProtectionLevel::High`         | `PROTECTION_LEVEL_HIGH`                      | `ProtectionLevel::High`       | `ProtectionLevel.HIGH`    | `ProtectionLevel.High`    |
| `Result<_, RegexError>`         | `NULL` + `char **error`                      | throws `RegexError`           | throws `RegexError`       | throws `RegexError`       |

A few names cannot be kept exactly:

- **C**: every function has the `mini_waf_` prefix, followed by the Rust
  path in snake_case. A public field is read through a `_get_<field>`
  function.
- **C++**: `requires` and `not` are keywords, so these methods are
  `requires_any` (the value must contain any of the literals) and
  `not_`. The unit `WafField` variants are static
  functions such as `WafField::Ip()`. The C API lives in
  `mini_waf::sys`.
- **.NET**: `WafField.Query` is the unit field, so the named accessor
  `WafField::Query(name)` is `WafField.QueryParam(name)`. `WafHttpContext`
  is an interface that keeps its Rust name, without the usual `I` prefix.

## Behaviour shared by all bindings

- **Ownership**:
  - In C, every `*_new` / `create_*` result has a matching `*_free`.
  - C++ uses RAII.
  - Java uses a `Cleaner` plus `close()`.
  - .NET uses a `SafeHandle` plus `Dispose()`.
  - Rules returned by an instance are views that live as long as the
    instance. Changing a view with a builder first turns it into an
    independent copy.
- **Threads**:
  - A `MiniWafInstance` or `CustomAdapter` can be shared across threads.
  - Evaluation is synchronous. Callbacks run on the calling thread before
    `handle` / `protect` returns.
- **Callbacks**:
  - An exception thrown by a handler, context method or predicate never
    unwinds through Rust. It is parked, the evaluation finishes, and the
    exception is rethrown from `handle` / `protect` / `is_match`.
  - A Rust panic is caught at the boundary and reported as a `NULL` result.
- **Not exposed**:
  - custom `WafLogger` sinks (logging goes to the console);
  - `WafEngineOptions` and the engine internals;
  - `RawBody::Json`;
  - the `WafAdapter` trait.

  Adapters are built with `create_adapter`, and a context is implemented
  with `WafHttpContext`.

## Formatting

Every language is kept to 80 columns by its usual tool, and CI checks all
of them:

```bash
# C and C++: clang-format (c/.clang-format, cpp/.clang-format)
pipx run clang-format==23.1.1 -i c/*/*.[ch] cpp/*/*.[ch]pp
# Java: Checkstyle (java/checkstyle.xml); it checks, it does not rewrite
cd java && mvn checkstyle:check
# .NET: CSharpier (dotnet/.csharpierrc.json)
cd dotnet && dotnet tool restore && dotnet csharpier format .
```

These formatters do not wrap comments, so wrap long comments by hand.

## Maintenance

- `rust-ffi/tests/header.rs` checks that `mini_waf.h` declares exactly the
  functions the crate exports.
- `java/.../Api.java` and `dotnet/MiniWaf/Api.cs` mirror the header one
  function per method. Keep them in sync when the header changes.
- CI has one workflow per language (`.github/workflows/`); each builds
  the library and runs that binding's tests and format check.
