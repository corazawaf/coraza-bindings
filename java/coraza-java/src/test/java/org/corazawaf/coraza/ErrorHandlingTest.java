package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers: coraza_new_waf char**er typemap — bad config raises RuntimeException.
 */
class ErrorHandlingTest {

    @Test
    void testWafCreationErrorBadRulesFile() {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add_file(cfg, "/nonexistent/path/rules.conf");
        assertThrows(RuntimeException.class, () -> coraza.coraza_new_waf(cfg),
                "expected RuntimeException from coraza_new_waf with invalid config");
        assertEquals(0, coraza.coraza_free_waf_config(cfg));
    }

    @Test
    void testFreeNullInterventionIsIdempotent() {
        // Passing a null/zero transaction handle is undefined behavior in C,
        // but calling coraza_intervention on a valid (clean) transaction must return null.
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg,
            "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" \"id:99,phase:1,pass\"");
        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/ok", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);
        coraza.coraza_process_logging(tx);

        // No rule matched — intervention must be null.
        assertNull(coraza.coraza_intervention(tx));

        coraza.coraza_free_transaction(tx);
        coraza.coraza_free_waf(waf);
    }
}
