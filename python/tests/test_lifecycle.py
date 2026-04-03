"""Full transaction lifecycle test.

Covers: coraza_new_waf_config, coraza_rules_add, coraza_rules_add_file,
        coraza_new_waf, coraza_rules_count, coraza_free_waf_config,
        coraza_new_transaction_with_id, coraza_process_connection,
        coraza_add_request_header, coraza_add_get_args,
        coraza_process_uri, coraza_process_request_headers,
        coraza_append_request_body, coraza_process_request_body,
        coraza_process_response_headers, coraza_add_response_header,
        coraza_append_response_body, coraza_process_response_body,
        coraza_update_status_code, coraza_process_logging,
        coraza_intervention, coraza_free_intervention,
        coraza_free_transaction, coraza_new_transaction, coraza_free_waf
"""

import os
import tempfile

import pytest
import coraza as _c
from .conftest import DENY_RULE, PASS_RULE


def test_waf_config_and_rules():
    cfg = _c.coraza_new_waf_config()
    assert cfg != 0, "coraza_new_waf_config returned 0"

    ret = _c.coraza_rules_add(cfg, DENY_RULE)
    assert ret == 0, f"coraza_rules_add failed: {ret}"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tf:
        tf.write(PASS_RULE + "\n")
        rules_file = tf.name
    try:
        ret = _c.coraza_rules_add_file(cfg, rules_file)
        assert ret == 0, f"coraza_rules_add_file failed: {ret}"

        waf = _c.coraza_new_waf(cfg)
        assert waf != 0, "coraza_new_waf returned 0"
    finally:
        os.unlink(rules_file)

    count = _c.coraza_rules_count(waf)
    assert count >= 2, f"expected >= 2 rules, got {count}"

    assert _c.coraza_free_waf_config(cfg) == 0
    assert _c.coraza_free_waf(waf) == 0


def test_full_request_response_lifecycle():
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, DENY_RULE)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tf:
        tf.write(PASS_RULE + "\n")
        rules_file = tf.name
    try:
        _c.coraza_rules_add_file(cfg, rules_file)
        waf = _c.coraza_new_waf(cfg)
    finally:
        os.unlink(rules_file)

    _c.coraza_free_waf_config(cfg)

    tx = _c.coraza_new_transaction_with_id(waf, "py-lifecycle-test")
    assert tx != 0, "coraza_new_transaction_with_id returned 0"

    assert _c.coraza_process_connection(tx, "127.0.0.1", 55555, "localhost", 80) == 0

    hname, hvalue = "Host", "localhost"
    assert _c.coraza_add_request_header(
        tx, hname, len(hname.encode()), hvalue, len(hvalue.encode())
    ) == 0

    assert _c.coraza_add_get_args(tx, "foo", "bar") == 0
    assert _c.coraza_process_uri(tx, "/someurl?foo=bar", "GET", "HTTP/1.1") == 0
    assert _c.coraza_process_request_headers(tx) == 0
    assert _c.coraza_append_request_body(tx, b"hello=world") == 0
    assert _c.coraza_process_request_body(tx) == 0
    assert _c.coraza_process_response_headers(tx, 200, "HTTP/1.1") == 0

    cname, cvalue = "Content-Type", "text/plain"
    assert _c.coraza_add_response_header(
        tx, cname, len(cname.encode()), cvalue, len(cvalue.encode())
    ) == 0

    assert _c.coraza_append_response_body(tx, b"OK") == 0
    assert _c.coraza_process_response_body(tx) == 0
    _c.coraza_update_status_code(tx, 200)
    assert _c.coraza_process_logging(tx) == 0

    # Deny rule on 127.0.0.1 must have fired.
    it = _c.coraza_intervention(tx)
    assert it is not None, "expected an intervention but got None"
    assert it.status == 403, f"expected status 403, got {it.status}"
    assert _c.coraza_free_intervention(it) == 0

    assert _c.coraza_free_transaction(tx) == 0

    # Non-ID variant
    tx2 = _c.coraza_new_transaction(waf)
    assert tx2 != 0, "coraza_new_transaction returned 0"
    _c.coraza_free_transaction(tx2)

    assert _c.coraza_free_waf(waf) == 0
