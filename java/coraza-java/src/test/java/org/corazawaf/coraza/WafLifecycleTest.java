package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full WAF + transaction lifecycle test against the raw SWIG layer.
 *
 * Covers: coraza_new_waf_config, coraza_rules_add, coraza_rules_add_file,
 *         coraza_new_waf, coraza_rules_count, coraza_free_waf_config,
 *         coraza_new_transaction_with_id, coraza_process_connection,
 *         coraza_add_request_header, coraza_add_get_args,
 *         coraza_process_uri, coraza_process_request_headers,
 *         coraza_append_request_body, coraza_process_request_body,
 *         coraza_process_response_headers, coraza_add_response_header,
 *         coraza_append_response_body, coraza_process_response_body,
 *         coraza_update_status_code, coraza_process_logging,
 *         coraza_intervention, coraza_free_intervention,
 *         coraza_free_transaction, coraza_new_transaction, coraza_free_waf
 */
class WafLifecycleTest {

    static final String DENY_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 127.0.0.1\" " +
        "\"id:1,phase:1,deny,log,msg:'block',status:403\"";

    static final String PASS_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" " +
        "\"id:2,phase:1,pass,log,msg:'allow'\"";

    @Test
    void testWafConfigAndRulesCount(@TempDir Path tmp) throws IOException {
        long cfg = coraza.coraza_new_waf_config();
        assertNotEquals(0, cfg, "coraza_new_waf_config returned 0");

        assertEquals(0, coraza.coraza_rules_add(cfg, DENY_RULE));

        Path rulesFile = tmp.resolve("rules.conf");
        try (FileWriter fw = new FileWriter(rulesFile.toFile())) {
            fw.write(PASS_RULE + "\n");
        }
        assertEquals(0, coraza.coraza_rules_add_file(cfg, rulesFile.toString()));

        long waf = coraza.coraza_new_waf(cfg);
        assertNotEquals(0, waf, "coraza_new_waf returned 0");
        assertTrue(coraza.coraza_rules_count(waf) >= 2,
                "expected >= 2 rules, got " + coraza.coraza_rules_count(waf));

        assertEquals(0, coraza.coraza_free_waf_config(cfg));
        assertEquals(0, coraza.coraza_free_waf(waf));
    }

    @Test
    void testFullRequestResponseLifecycle(@TempDir Path tmp) throws IOException {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, DENY_RULE);

        Path rulesFile = tmp.resolve("rules.conf");
        try (FileWriter fw = new FileWriter(rulesFile.toFile())) {
            fw.write(PASS_RULE + "\n");
        }
        coraza.coraza_rules_add_file(cfg, rulesFile.toString());
        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction_with_id(waf, "java-lifecycle-test");
        assertNotEquals(0, tx);

        assertEquals(0, coraza.coraza_process_connection(tx, "127.0.0.1", 55555, "localhost", 80));

        String hname = "Host", hvalue = "localhost";
        assertEquals(0, coraza.coraza_add_request_header(tx, hname, hname.length(), hvalue, hvalue.length()));
        assertEquals(0, coraza.coraza_add_get_args(tx, "foo", "bar"));
        assertEquals(0, coraza.coraza_process_uri(tx, "/someurl?foo=bar", "GET", "HTTP/1.1"));
        assertEquals(0, coraza.coraza_process_request_headers(tx));
        assertEquals(0, coraza.coraza_append_request_body(tx, "hello=world".getBytes()));
        assertEquals(0, coraza.coraza_process_request_body(tx));
        assertEquals(0, coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1"));

        String cname = "Content-Type", cvalue = "text/plain";
        assertEquals(0, coraza.coraza_add_response_header(tx, cname, cname.length(), cvalue, cvalue.length()));
        assertEquals(0, coraza.coraza_append_response_body(tx, "OK".getBytes()));
        assertEquals(0, coraza.coraza_process_response_body(tx));
        coraza.coraza_update_status_code(tx, 200);
        assertEquals(0, coraza.coraza_process_logging(tx));

        var it = coraza.coraza_intervention(tx);
        assertNotNull(it, "expected an intervention but got null");
        assertEquals(403, it.getStatus());
        assertEquals(0, coraza.coraza_free_intervention(it));
        assertEquals(0, coraza.coraza_free_transaction(tx));

        long tx2 = coraza.coraza_new_transaction(waf);
        assertNotEquals(0, tx2);
        coraza.coraza_free_transaction(tx2);
        assertEquals(0, coraza.coraza_free_waf(waf));
    }
}
