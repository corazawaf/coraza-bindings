"""Rules merge test.

Covers: coraza_rules_merge
NOTE: coraza_rules_merge is currently a stub (always returns 0, does not
actually merge rules). This test only verifies the call does not crash.
"""

import coraza as _c
from .conftest import PASS_RULE


def test_rules_merge_does_not_crash():
    cfg1 = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg1, PASS_RULE)
    waf1 = _c.coraza_new_waf(cfg1)
    assert _c.coraza_free_waf_config(cfg1) == 0

    cfg2 = _c.coraza_new_waf_config()
    waf2 = _c.coraza_new_waf(cfg2)
    assert _c.coraza_free_waf_config(cfg2) == 0

    ret = _c.coraza_rules_merge(waf1, waf2)
    assert ret == 0, f"coraza_rules_merge failed: {ret}"

    assert _c.coraza_free_waf(waf1) == 0
    assert _c.coraza_free_waf(waf2) == 0
