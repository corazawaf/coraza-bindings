package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers: coraza_rules_merge
 * NOTE: coraza_rules_merge is currently a stub (always returns 0, does not
 * actually merge rules). This test only verifies the call does not crash.
 */
class RulesMergeTest {

    static final String PASS_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" " +
        "\"id:2,phase:1,pass,log,msg:'allow'\"";

    @Test
    void testRulesMergeDoesNotCrash() {
        long cfg1 = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg1, PASS_RULE);
        long waf1 = coraza.coraza_new_waf(cfg1);
        assertEquals(0, coraza.coraza_free_waf_config(cfg1));

        long cfg2 = coraza.coraza_new_waf_config();
        long waf2 = coraza.coraza_new_waf(cfg2);
        assertEquals(0, coraza.coraza_free_waf_config(cfg2));

        assertEquals(0, coraza.coraza_rules_merge(waf1, waf2),
                "coraza_rules_merge failed");

        assertEquals(0, coraza.coraza_free_waf(waf1));
        assertEquals(0, coraza.coraza_free_waf(waf2));
    }
}
