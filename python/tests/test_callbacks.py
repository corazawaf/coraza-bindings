"""Callback tests.

Covers: coraza_set_error_callback, coraza_set_debug_log_callback,
        coraza_matched_rule_get_error_log, coraza_matched_rule_get_severity
"""

import coraza as _c
from .conftest import DENY_RULE


def test_error_callback_fires():
    matched_logs = []

    def on_error(rule_handle):
        log = _c.coraza_matched_rule_get_error_log(rule_handle)
        sev = _c.coraza_matched_rule_get_severity(rule_handle)
        matched_logs.append((sev, log))

    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, DENY_RULE)
    assert _c.coraza_set_error_callback(cfg, on_error) == 0

    waf = _c.coraza_new_waf(cfg)
    assert _c.coraza_free_waf_config(cfg) == 0

    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_logging(tx)
    assert _c.coraza_free_transaction(tx) == 0
    assert _c.coraza_free_waf(waf) == 0

    assert len(matched_logs) > 0, "expected at least one matched rule via error callback"


def test_debug_log_callback_accepted():
    """The debug callback must be accepted (return 0) without asserting message count,
    as Coraza's default log level is ERROR."""
    debug_msgs = []

    def on_debug(level, message, fields):
        debug_msgs.append((level, message))

    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, DENY_RULE)
    assert _c.coraza_set_debug_log_callback(cfg, on_debug) == 0

    waf = _c.coraza_new_waf(cfg)
    assert _c.coraza_free_waf_config(cfg) == 0
    assert _c.coraza_free_waf(waf) == 0


def test_both_callbacks_together():
    matched = []
    debug = []

    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, DENY_RULE)
    assert _c.coraza_set_error_callback(cfg, lambda h: matched.append(h)) == 0
    assert _c.coraza_set_debug_log_callback(cfg, lambda l, m, f: debug.append(m)) == 0

    waf = _c.coraza_new_waf(cfg)
    assert _c.coraza_free_waf_config(cfg) == 0

    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_logging(tx)
    assert _c.coraza_free_transaction(tx) == 0
    assert _c.coraza_free_waf(waf) == 0

    assert len(matched) > 0, "expected at least one matched rule"
