package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.corazawaf.coraza.internal.swig.coraza_intervention_t;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers: coraza_intervention .data field (redirect URL).
 * Validates the char *data struct field end-to-end through the SWIG layer.
 */
class InterventionRedirectTest {

    static final String REDIRECT_RULE =
        "SecRule ARGS:trigger \"@streq yes\" " +
        "\"id:10,phase:1,status:302,redirect:http://example.com\"";

    @Test
    void testInterventionRedirect() {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, REDIRECT_RULE);
        long waf = coraza.coraza_new_waf(cfg);
        assertEquals(0, coraza.coraza_free_waf_config(cfg));

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_add_get_args(tx, "trigger", "yes");
        coraza.coraza_process_uri(tx, "/?trigger=yes", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);

        coraza_intervention_t it = coraza.coraza_intervention(tx);
        assertNotNull(it, "expected a redirect intervention but got null");
        assertEquals(302, it.getStatus(), "expected status 302");
        assertEquals("redirect", it.getAction(), "expected action 'redirect'");
        assertEquals("http://example.com", it.getData(), "expected data 'http://example.com'");

        assertEquals(0, coraza.coraza_free_intervention(it));
        assertEquals(0, coraza.coraza_free_transaction(tx));
        assertEquals(0, coraza.coraza_free_waf(waf));
    }

    @Test
    void testNoInterventionOnCleanRequest() {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg,
            "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" \"id:2,phase:1,pass\"");
        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/ok", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);
        coraza.coraza_process_logging(tx);

        assertNull(coraza.coraza_intervention(tx), "expected no intervention");

        coraza.coraza_free_transaction(tx);
        coraza.coraza_free_waf(waf);
    }
}
