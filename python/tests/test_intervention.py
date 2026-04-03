"""Intervention tests, including redirect with data field.

Covers: coraza_intervention, coraza_free_intervention,
        coraza_intervention_t.status / .action / .data
"""

import coraza as _c
from .conftest import DENY_RULE


REDIRECT_RULE = (
    'SecRule ARGS:trigger "@streq yes" '
    '"id:10,phase:1,status:302,redirect:http://example.com"'
)


def test_intervention_deny(deny_waf):
    tx = _c.coraza_new_transaction(deny_waf)
    _c.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_logging(tx)

    it = _c.coraza_intervention(tx)
    assert it is not None, "expected an intervention but got None"
    assert it.status == 403, f"expected status 403, got {it.status}"
    assert it.action == "deny", f"expected action 'deny', got {it.action!r}"

    assert _c.coraza_free_intervention(it) == 0
    assert _c.coraza_free_transaction(tx) == 0


def test_intervention_redirect():
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, REDIRECT_RULE)
    waf = _c.coraza_new_waf(cfg)
    assert _c.coraza_free_waf_config(cfg) == 0

    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_add_get_args(tx, "trigger", "yes")
    _c.coraza_process_uri(tx, "/?trigger=yes", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)

    it = _c.coraza_intervention(tx)
    assert it is not None, "expected a redirect intervention but got None"
    assert it.status == 302, f"expected status 302, got {it.status}"
    assert it.action == "redirect", f"expected action 'redirect', got {it.action!r}"
    assert it.data == "http://example.com", (
        f"expected data 'http://example.com', got {it.data!r}"
    )

    assert _c.coraza_free_intervention(it) == 0
    assert _c.coraza_free_transaction(tx) == 0
    assert _c.coraza_free_waf(waf) == 0


def test_no_intervention_on_clean_request(pass_waf):
    tx = _c.coraza_new_transaction(pass_waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/ok", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_logging(tx)

    it = _c.coraza_intervention(tx)
    assert it is None, f"expected no intervention but got {it}"

    assert _c.coraza_free_transaction(tx) == 0
