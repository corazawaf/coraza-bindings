"""Shared pytest fixtures for coraza Python binding tests."""

import pytest
import coraza as _c

DENY_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" '
    '"id:1,phase:1,deny,log,msg:\'block\',status:403"'
)
PASS_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" '
    '"id:2,phase:1,pass,log,msg:\'allow\'"'
)


@pytest.fixture()
def deny_waf():
    """WAF with a single deny rule on 127.0.0.1."""
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, DENY_RULE)
    waf = _c.coraza_new_waf(cfg)
    _c.coraza_free_waf_config(cfg)
    yield waf
    _c.coraza_free_waf(waf)


@pytest.fixture()
def pass_waf():
    """WAF with a single pass rule on 10.0.0.1."""
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, PASS_RULE)
    waf = _c.coraza_new_waf(cfg)
    _c.coraza_free_waf_config(cfg)
    yield waf
    _c.coraza_free_waf(waf)
