"""Error handling and input validation tests.

Covers: coraza_new_waf with bad config (RuntimeError),
        byte typemap validation, PyCallable_Check hardening.
"""

import pytest
import coraza as _c
from coraza import CorazaException


def test_waf_creation_error_bad_rules_file():
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add_file(cfg, "/nonexistent/path/rules.conf")
    with pytest.raises(RuntimeError):
        _c.coraza_new_waf(cfg)
    assert _c.coraza_free_waf_config(cfg) == 0


def test_append_request_body_rejects_str():
    cfg = _c.coraza_new_waf_config()
    waf = _c.coraza_new_waf(cfg)
    _c.coraza_free_waf_config(cfg)
    tx = _c.coraza_new_transaction(waf)

    with pytest.raises(TypeError):
        _c.coraza_append_request_body(tx, "not bytes")

    _c.coraza_free_transaction(tx)
    _c.coraza_free_waf(waf)


def test_append_response_body_rejects_str():
    cfg = _c.coraza_new_waf_config()
    waf = _c.coraza_new_waf(cfg)
    _c.coraza_free_waf_config(cfg)
    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 0, "localhost", 80)
    _c.coraza_process_uri(tx, "/", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_response_headers(tx, 200, "HTTP/1.1")

    with pytest.raises(TypeError):
        _c.coraza_append_response_body(tx, "not bytes")

    _c.coraza_free_transaction(tx)
    _c.coraza_free_waf(waf)


def test_error_callback_rejects_non_callable():
    cfg = _c.coraza_new_waf_config()
    with pytest.raises(TypeError):
        _c.coraza_set_error_callback(cfg, "not a callable")
    assert _c.coraza_free_waf_config(cfg) == 0


def test_error_callback_rejects_int():
    cfg = _c.coraza_new_waf_config()
    with pytest.raises(TypeError):
        _c.coraza_set_error_callback(cfg, 42)
    assert _c.coraza_free_waf_config(cfg) == 0


def test_debug_callback_rejects_non_callable():
    cfg = _c.coraza_new_waf_config()
    with pytest.raises(TypeError):
        _c.coraza_set_debug_log_callback(cfg, "not a callable")
    assert _c.coraza_free_waf_config(cfg) == 0
