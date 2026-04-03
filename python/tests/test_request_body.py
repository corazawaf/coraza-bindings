"""Request body tests.

Covers: coraza_request_body_from_file, coraza_append_request_body
"""

import os
import tempfile

import coraza as _c


def test_request_body_from_file(pass_waf):
    tx = _c.coraza_new_transaction(pass_waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"body content from file")
        body_file = tf.name
    try:
        ret = _c.coraza_request_body_from_file(tx, body_file)
        assert ret == 0, f"coraza_request_body_from_file failed: {ret}"
    finally:
        os.unlink(body_file)

    assert _c.coraza_process_request_body(tx) == 0
    assert _c.coraza_process_response_headers(tx, 200, "HTTP/1.1") == 0
    assert _c.coraza_process_response_body(tx) == 0
    assert _c.coraza_process_logging(tx) == 0
    assert _c.coraza_free_transaction(tx) == 0


def test_append_request_body_bytes(pass_waf):
    tx = _c.coraza_new_transaction(pass_waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)

    assert _c.coraza_append_request_body(tx, b"key=value") == 0
    assert _c.coraza_process_request_body(tx) == 0
    assert _c.coraza_free_transaction(tx) == 0


def test_append_request_body_bytearray(pass_waf):
    tx = _c.coraza_new_transaction(pass_waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)

    assert _c.coraza_append_request_body(tx, bytearray(b"key=value")) == 0
    assert _c.coraza_process_request_body(tx) == 0
    assert _c.coraza_free_transaction(tx) == 0
