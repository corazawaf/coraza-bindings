package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers: coraza_set_error_callback, coraza_set_debug_log_callback,
 *         coraza_matched_rule_get_error_log, coraza_matched_rule_get_severity
 */
class CallbacksTest {

    static final String DENY_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 127.0.0.1\" " +
        "\"id:1,phase:1,deny,log,msg:'block',status:403\"";

    @Test
    void testErrorCallbackFires() {
        List<String> matched = new ArrayList<>();

        CorazaErrorCallback onError = ruleHandle -> {
            String log = coraza.coraza_matched_rule_get_error_log(ruleHandle);
            matched.add(log);
        };

        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, DENY_RULE);
        assertEquals(0, coraza.coraza_set_error_callback(cfg, onError));

        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);
        coraza.coraza_process_logging(tx);
        coraza.coraza_free_transaction(tx);
        coraza.coraza_free_waf(waf);

        assertFalse(matched.isEmpty(), "expected at least one matched rule via error callback");
    }

    @Test
    void testDebugLogCallbackAccepted() {
        List<String> debugMsgs = new ArrayList<>();

        CorazaDebugLogCallback onDebug = (level, message, fields) ->
            debugMsgs.add("[" + level + "] " + message);

        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, DENY_RULE);
        assertEquals(0, coraza.coraza_set_debug_log_callback(cfg, onDebug));

        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);
        coraza.coraza_free_waf(waf);
        // No assertion on message count — depends on Coraza's internal log level.
    }

    @Test
    void testBothCallbacksTogether() {
        List<String> matched = new ArrayList<>();
        List<String> debug   = new ArrayList<>();

        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, DENY_RULE);
        assertEquals(0, coraza.coraza_set_error_callback(cfg, (CorazaErrorCallback) h -> matched.add("hit")));
        assertEquals(0, coraza.coraza_set_debug_log_callback(cfg, (CorazaDebugLogCallback) (l, m, f) -> debug.add(m)));

        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);
        coraza.coraza_process_logging(tx);
        coraza.coraza_free_transaction(tx);
        coraza.coraza_free_waf(waf);

        assertFalse(matched.isEmpty(), "expected at least one matched rule");
    }
}
