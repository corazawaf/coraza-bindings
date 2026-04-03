package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers: coraza_request_body_from_file
 */
class RequestBodyFromFileTest {

    static final String PASS_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" " +
        "\"id:2,phase:1,pass,log,msg:'allow'\"";

    @Test
    void testRequestBodyFromFile(@TempDir Path tmp) throws IOException {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, PASS_RULE);
        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);

        Path bodyFile = tmp.resolve("body.txt");
        try (FileWriter fw = new FileWriter(bodyFile.toFile())) {
            fw.write("body content from file");
        }

        assertEquals(0, coraza.coraza_request_body_from_file(tx, bodyFile.toString()),
                "coraza_request_body_from_file failed");

        assertEquals(0, coraza.coraza_process_request_body(tx));
        assertEquals(0, coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1"));
        assertEquals(0, coraza.coraza_process_response_body(tx));
        assertEquals(0, coraza.coraza_process_logging(tx));
        assertEquals(0, coraza.coraza_free_transaction(tx));
        assertEquals(0, coraza.coraza_free_waf(waf));
    }
}
