# coraza-java

Java bindings for [libcoraza](https://github.com/corazawaf/libcoraza) — the C library wrapping
[OWASP Coraza WAF](https://github.com/corazawaf/coraza).

## Requirements

| Tool | Version |
|------|---------|
| Java | 11+ |
| Maven | 3.8+ |
| SWIG | 4.x |
| GCC | 9+ |
| Go | 1.21+ (to build libcoraza) |

## Quick start

### 1. Build libcoraza

```bash
bash ../scripts/fetch-libcoraza.sh 1.2.2
export LIBCORAZA_ROOT=/tmp/libcoraza-1.2.2
```

### 2. Build and test

```bash
cd coraza-java
mvn -B verify
```

Maven will:
1. Run `scripts/build-native-java.sh` (SWIG + GCC) to produce `libcoraza_jni.{so,dylib}`
2. Add SWIG-generated Java sources to the compile source roots
3. Compile all sources
4. Run JUnit 5 tests with the native library on the classpath

---

## API overview

### `Waf.Builder`

```java
Waf waf = new Waf.Builder()
    .rule("SecRule REMOTE_ADDR \"@ipMatch 127.0.0.1\" \"id:1,phase:1,deny,status:403\"")
    .onRuleMatch(ruleId -> System.out.println("Rule matched: " + ruleId))
    .onDebugLog((level, message, fields) -> logger.debug("[{}] {}", level, message))
    .build();
```

`build()` throws `CorazaException` if the WAF cannot be created (e.g. invalid rule directive).

### `Transaction`

```java
try (Waf waf = new Waf.Builder().rule(DENY_RULE).build();
     Transaction tx = waf.newTransaction()) {

    tx.processConnection("1.2.3.4", 12345, "example.com", 443);
    tx.addRequestHeader("Host", "example.com");
    tx.processUri("/login", "POST", "HTTP/1.1");
    tx.processRequestHeaders();
    tx.appendRequestBody("user=admin&pass=secret".getBytes());
    tx.processRequestBody();

    tx.intervention().ifPresent(it -> {
        try (it) {
            // it.getStatus() — HTTP status to return (e.g. 403)
            // it.getAction() — "deny" or "redirect"
            // it.getData()   — redirect URL (null for deny)
        }
    });
}
```

`Transaction` and `Waf` are both `AutoCloseable` — use them in try-with-resources.

### `Intervention`

```java
Optional<Intervention> maybeIt = tx.intervention();
if (maybeIt.isPresent()) {
    try (Intervention it = maybeIt.get()) {
        int status   = it.getStatus();   // e.g. 403, 302
        String action = it.getAction();  // "deny" or "redirect"
        String data   = it.getData();    // redirect URL, or null
    }
}
```

`intervention()` never returns `null` — it returns `Optional.empty()` when there is no
intervention, so callers never need to null-check.

### Callbacks

```java
// Rule-match callback — fired once per matched rule
Waf waf = new Waf.Builder()
    .rule(DENY_RULE)
    .onRuleMatch(ruleId -> metrics.increment("coraza.rule_matched", "id:" + ruleId))
    .build();

// Debug-log callback — volume depends on Coraza's internal log level
Waf waf = new Waf.Builder()
    .rule(DENY_RULE)
    .onDebugLog((level, message, fields) -> System.err.printf("[%d] %s%n", level, message))
    .build();
```

### `CorazaException`

Thrown by `Waf.Builder.build()` when WAF creation fails (e.g. invalid rule file path,
bad directive). Extends `RuntimeException` — callers can catch it without declaring it.

```java
try {
    Waf waf = new Waf.Builder().rulesFile("/nonexistent/rules.conf").build();
} catch (CorazaException e) {
    System.err.println("WAF init failed: " + e.getMessage());
}
```

---

## Package structure

```
org.corazawaf.coraza
├── Waf.java                   # Entry point: Waf.Builder + Waf
├── Transaction.java           # Transaction lifecycle
├── Intervention.java          # Intervention result (deny / redirect)
├── CorazaException.java       # Thrown on WAF init failure
├── CorazaErrorCallback.java   # Functional interface for rule-match events
├── CorazaDebugLogCallback.java# Functional interface for debug log messages
└── internal/
    ├── NativeLoader.java      # Extracts platform JNI lib from fat JAR at runtime
    └── swig/                  # SWIG-generated sources (not committed; built by Maven)
        ├── coraza.java
        ├── corazaJNI.java
        └── coraza_intervention_t.java
```

---

## Low-level SWIG API

All generated SWIG functions are accessible via `org.corazawaf.coraza.internal.swig.coraza`.
This is the raw C-to-Java bridge — use the high-level API above in production code.

```java
import org.corazawaf.coraza.internal.swig.coraza;
import org.corazawaf.coraza.internal.swig.coraza_intervention_t;

long cfg = coraza.coraza_new_waf_config();
coraza.coraza_rules_add(cfg, "SecRule ...");
long waf = coraza.coraza_new_waf(cfg);
coraza.coraza_free_waf_config(cfg);

long tx = coraza.coraza_new_transaction(waf);
coraza.coraza_process_connection(tx, "1.2.3.4", 12345, "host", 80);
coraza.coraza_process_uri(tx, "/", "GET", "HTTP/1.1");
coraza.coraza_process_request_headers(tx);
coraza.coraza_process_logging(tx);

coraza_intervention_t it = coraza.coraza_intervention(tx);
// it == null → no intervention

coraza.coraza_free_transaction(tx);
coraza.coraza_free_waf(waf);
```

---

## Code style

The Java public API follows these conventions:

- **Fluent builder**: `Waf.Builder` methods return `this` for chaining.
- **try-with-resources**: `Waf`, `Transaction`, and `Intervention` implement `AutoCloseable`.
  Always use them in try-with-resources (or explicitly call `free()`).
- **`Optional` for nullable results**: `Transaction.intervention()` returns
  `Optional<Intervention>` — never `null`.
- **`CorazaException extends RuntimeException`**: Thrown only at WAF creation time.
  Transaction-level operations return `int` status codes.
- **Idempotent `free()`**: calling `free()` or closing multiple times is safe.
- **`getData()` returns `null` (not `""`)**: an empty `data` field means no redirect URL.
- **Javadoc on all public members**: with `@param`, `@return`, `@throws`, and usage snippets.

---

## License

Apache License 2.0 — see [LICENSE](../LICENSE).
