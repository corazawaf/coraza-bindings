# coraza — Python bindings for OWASP Coraza WAF

Python SWIG bindings for [libcoraza](https://github.com/corazawaf/libcoraza).

See the [repository README](../README.md) for build instructions.

## Quick start

```python
from coraza import Waf

with Waf.from_rules(
    "SecRuleEngine On",
    'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:1,phase:1,deny,status:403"',
) as waf:
    with waf.new_transaction() as tx:
        tx.process_connection("10.0.0.1", 12345, "app.example.com", 443)
        tx.process_uri("/", "GET", "HTTP/1.1")
        tx.process_request_headers()
        tx.process_logging()

        it = tx.intervention()
        if it is not None:
            with it:
                print(f"Blocked: HTTP {it.status} — action={it.action}")
```

## Usage examples

### 1. Basic deny rule

Create a WAF with an inline deny rule, process a connection, and check whether the request was blocked.

```python
from coraza import Waf, CorazaException

rule = (
    'SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" '
    '"id:100,phase:1,deny,status:403,msg:\'Blocked IP\'"'
)

try:
    waf = Waf.from_rules("SecRuleEngine On", rule)
except CorazaException as exc:
    raise SystemExit(f"Invalid WAF configuration: {exc}")

print(f"Rules loaded: {waf.rules_count}")

with waf:
    with waf.new_transaction() as tx:
        tx.process_connection("192.168.1.100", 54321, "10.0.0.1", 80)
        tx.process_uri("/login", "POST", "HTTP/1.1")
        tx.add_request_header("Host", "example.com")
        tx.process_request_headers()
        tx.process_logging()

        it = tx.intervention()
        if it is not None:
            with it:
                # it.status == 403, it.action == "deny"
                print(f"Request denied: status={it.status}, action={it.action}")
        else:
            print("Request allowed")
```

### 2. Redirect rule

A rule that issues a redirect instead of a deny. Use `it.data` to obtain the redirect target URL.

```python
from coraza import Waf

redirect_rule = (
    'SecRule REQUEST_URI "@beginsWith /old/" '
    '"id:200,phase:1,redirect:http://example.com/new/,status:302"'
)

with Waf.from_rules("SecRuleEngine On", redirect_rule) as waf:
    with waf.new_transaction() as tx:
        tx.process_connection("1.2.3.4", 9000, "app.example.com", 80)
        tx.process_uri("/old/page.html", "GET", "HTTP/1.1")
        tx.process_request_headers()
        tx.process_logging()

        it = tx.intervention()
        if it is not None:
            with it:
                # it.action == "redirect", it.data == "http://example.com/new/"
                print(f"Redirect to: {it.data} (HTTP {it.status})")
```

### 3. Error callback

Register an error callback to receive a handle for each rule that fires. The callback is invoked from native code — keep it short and thread-safe.

```python
from coraza import (
    Waf,
    coraza_new_waf_config,
    coraza_rules_add,
    coraza_matched_rule_get_error_log,
    coraza_matched_rule_get_severity,
)

def on_rule_match(rule_handle: int) -> None:
    log_line = coraza_matched_rule_get_error_log(rule_handle)
    severity = coraza_matched_rule_get_severity(rule_handle)
    print(f"[severity={severity}] {log_line}")

cfg = coraza_new_waf_config()
coraza_rules_add(cfg, "SecRuleEngine On")
coraza_rules_add(
    cfg,
    'SecRule ARGS "@contains attack" "id:300,phase:2,deny,status:400"',
)

with Waf.from_config(cfg, error_callback=on_rule_match) as waf:
    with waf.new_transaction() as tx:
        tx.process_connection("1.2.3.4", 4000, "app.example.com", 443)
        tx.process_uri("/search?q=attack", "GET", "HTTP/1.1")
        tx.add_get_args("q", "attack")
        tx.process_request_headers()
        tx.process_request_body()
        tx.process_logging()

        it = tx.intervention()
        if it is not None:
            with it:
                print(f"Blocked: {it.status}")
```

### 4. Debug log callback

Register a debug callback to capture low-level WAF log messages. Useful during rule development and troubleshooting.

```python
from coraza import (
    Waf,
    coraza_new_waf_config,
    coraza_rules_add,
    CORAZA_DEBUG_LOG_LEVEL_DEBUG,
)

def on_debug(level: int, message: str, fields: str) -> None:
    if level >= CORAZA_DEBUG_LOG_LEVEL_DEBUG:
        print(f"[DEBUG level={level}] {message} | {fields}")

cfg = coraza_new_waf_config()
coraza_rules_add(cfg, "SecRuleEngine On")
coraza_rules_add(cfg, 'SecRule REMOTE_ADDR "@ipMatch 0.0.0.0/0" "id:1,phase:1,pass"')

with Waf.from_config(cfg, debug_callback=on_debug) as waf:
    with waf.new_transaction() as tx:
        tx.process_connection("10.0.0.1", 1234, "10.0.0.2", 80)
        tx.process_uri("/", "GET", "HTTP/1.1")
        tx.process_request_headers()
        tx.process_logging()
```

### 5. Direct SWIG API

For maximum control, use the low-level SWIG functions directly. This mirrors the libcoraza C API.

```python
from coraza import (
    coraza_new_waf_config,
    coraza_rules_add,
    coraza_new_waf,
    coraza_free_waf_config,
    coraza_rules_count,
    coraza_new_transaction,
    coraza_free_transaction,
    coraza_process_connection,
    coraza_process_uri,
    coraza_add_get_args,
    coraza_process_request_headers,
    coraza_process_request_body,
    coraza_process_logging,
    coraza_intervention,
    coraza_free_intervention,
    coraza_free_waf,
)

# Build config
cfg = coraza_new_waf_config()
coraza_rules_add(cfg, "SecRuleEngine On")
coraza_rules_add(
    cfg,
    'SecRule ARGS "@contains <script>" "id:500,phase:2,deny,status:403"',
)

# Compile WAF (cfg is consumed after this call — do not reuse)
waf = coraza_new_waf(cfg)
coraza_free_waf_config(cfg)

print(f"Rules loaded: {coraza_rules_count(waf)}")

# Create and process a transaction
tx = coraza_new_transaction(waf)
try:
    coraza_process_connection(tx, "1.2.3.4", 5000, "app.example.com", 443)
    coraza_process_uri(tx, "/search", "GET", "HTTP/1.1")
    coraza_add_get_args(tx, "q", "<script>alert(1)</script>")
    coraza_process_request_headers(tx)
    coraza_process_request_body(tx)
    coraza_process_logging(tx)

    raw_it = coraza_intervention(tx)
    if raw_it is not None:
        print(f"Intervention: status={raw_it.status}, action={raw_it.action}")
        coraza_free_intervention(raw_it)
    else:
        print("No intervention")
finally:
    coraza_free_transaction(tx)

coraza_free_waf(waf)
```
