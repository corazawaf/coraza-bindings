"""High-level Waf / Transaction / Intervention API tests.

Tests the Python wrapper classes in coraza/__init__.py.
"""

import os
import tempfile

import pytest
import coraza
from coraza import Waf, Transaction, Intervention, CorazaException


DENY_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" '
    '"id:1,phase:1,deny,log,msg:\'block\',status:403"'
)
PASS_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" '
    '"id:2,phase:1,pass,log,msg:\'allow\'"'
)
REDIRECT_RULE = (
    'SecRule ARGS:trigger "@streq yes" '
    '"id:10,phase:1,status:302,redirect:http://example.com"'
)


# ---------------------------------------------------------------------------
# Waf class
# ---------------------------------------------------------------------------

def test_waf_from_rules():
    with Waf.from_rules(DENY_RULE, PASS_RULE) as waf:
        assert waf.rules_count >= 2


def test_waf_from_rules_invalid_raises():
    # coraza_rules_add() returns 0 for any string; the error surfaces at
    # coraza_new_waf() time when Coraza actually parses the directives.
    # from_rules() wraps that RuntimeError as CorazaException.
    with pytest.raises(CorazaException):
        Waf.from_rules("this is not a valid SecRule")


def test_waf_from_rules_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(DENY_RULE + "\n")
        path = f.name
    try:
        cfg = coraza.coraza_new_waf_config()
        coraza.coraza_rules_add_file(cfg, path)
        with Waf.from_config(cfg) as waf:
            assert waf.rules_count >= 1
    finally:
        os.unlink(path)


def test_waf_context_manager_frees():
    waf = Waf.from_rules(DENY_RULE)
    with waf:
        pass
    # Second free should be idempotent (returns 0, doesn't crash)
    assert waf.free() == 0


def test_waf_rules_count_zero_rules():
    cfg = coraza.coraza_new_waf_config()
    waf = Waf.from_config(cfg)
    with waf:
        assert waf.rules_count == 0


# ---------------------------------------------------------------------------
# Transaction class
# ---------------------------------------------------------------------------

def test_transaction_context_manager():
    with Waf.from_rules(PASS_RULE) as waf:
        with waf.new_transaction() as tx:
            assert tx.process_connection("10.0.0.1", 12345, "localhost", 80) == 0


def test_transaction_with_id():
    with Waf.from_rules(PASS_RULE) as waf:
        with waf.new_transaction_with_id("tx-abc-123") as tx:
            assert tx.process_connection("10.0.0.1", 12345, "localhost", 80) == 0


def test_transaction_full_lifecycle_deny():
    with Waf.from_rules(DENY_RULE) as waf:
        with waf.new_transaction() as tx:
            assert tx.process_connection("127.0.0.1", 55555, "localhost", 80) == 0
            assert tx.add_request_header("Host", "localhost") == 0
            assert tx.add_get_args("q", "test") == 0
            assert tx.process_uri("/search?q=test", "GET", "HTTP/1.1") == 0
            assert tx.process_request_headers() == 0
            assert tx.append_request_body(b"") == 0
            assert tx.process_request_body() == 0
            assert tx.process_response_headers(200, "HTTP/1.1") == 0
            assert tx.add_response_header("Content-Type", "text/html") == 0
            assert tx.append_response_body(b"<html/>") == 0
            assert tx.process_response_body() == 0
            tx.update_status_code(403)
            assert tx.process_logging() == 0

            it = tx.intervention()
            assert it is not None
            assert it.status == 403
            assert it.action == "deny"
            it.free()


def test_transaction_full_lifecycle_pass():
    with Waf.from_rules(PASS_RULE) as waf:
        with waf.new_transaction() as tx:
            assert tx.process_connection("10.0.0.1", 12345, "localhost", 80) == 0
            assert tx.process_uri("/ok", "GET", "HTTP/1.1") == 0
            assert tx.process_request_headers() == 0
            assert tx.process_response_headers(200, "HTTP/1.1") == 0
            assert tx.process_response_body() == 0
            assert tx.process_logging() == 0
            assert tx.intervention() is None


def test_transaction_request_body_from_file():
    with Waf.from_rules(PASS_RULE) as waf:
        with waf.new_transaction() as tx:
            tx.process_connection("10.0.0.1", 0, "localhost", 80)
            tx.process_uri("/upload", "POST", "HTTP/1.1")
            tx.process_request_headers()
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"file content")
                path = f.name
            try:
                assert tx.request_body_from_file(path) == 0
            finally:
                os.unlink(path)


def test_transaction_free_idempotent():
    with Waf.from_rules(PASS_RULE) as waf:
        tx = waf.new_transaction()
        assert tx.free() == 0
        assert tx.free() == 0  # second call must be safe


# ---------------------------------------------------------------------------
# Intervention class
# ---------------------------------------------------------------------------

def test_intervention_context_manager():
    with Waf.from_rules(REDIRECT_RULE) as waf:
        with waf.new_transaction() as tx:
            tx.process_connection("10.0.0.1", 12345, "localhost", 80)
            tx.add_get_args("trigger", "yes")
            tx.process_uri("/?trigger=yes", "GET", "HTTP/1.1")
            tx.process_request_headers()

            with tx.intervention() as it:
                assert it is not None
                assert it.status == 302
                assert it.action == "redirect"
                assert it.data == "http://example.com"


def test_transaction_free_after_context_manager_idempotent():
    """Calling free() after the context manager has already freed is safe."""
    with Waf.from_rules(PASS_RULE) as waf:
        tx = waf.new_transaction_with_id("idem-test")
        with tx:
            tx.process_connection("10.0.0.1", 0, "localhost", 80)
        # tx already freed by context manager exit
        assert tx.free() == 0
