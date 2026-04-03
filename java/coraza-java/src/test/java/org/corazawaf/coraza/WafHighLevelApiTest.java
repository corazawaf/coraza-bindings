package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * High-level API tests: Waf.Builder, Transaction, Intervention AutoCloseable,
 * Optional return type, CorazaException, callbacks.
 */
class WafHighLevelApiTest {

    static final String DENY_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 127.0.0.1\" " +
        "\"id:1,phase:1,deny,log,msg:'block',status:403\"";

    static final String PASS_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" " +
        "\"id:2,phase:1,pass,log,msg:'allow'\"";

    static final String REDIRECT_RULE =
        "SecRule ARGS:trigger \"@streq yes\" " +
        "\"id:10,phase:1,status:302,redirect:http://example.com\"";

    // ------------------------------------------------------------------
    // Waf.Builder
    // ------------------------------------------------------------------

    @Test
    void testBuilderWithInlineRule() {
        try (Waf waf = new Waf.Builder().rule(DENY_RULE).build()) {
            assertTrue(waf.getRulesCount() >= 1);
        }
    }

    @Test
    void testBuilderWithRulesFile(@TempDir Path tmp) throws IOException {
        Path f = tmp.resolve("rules.conf");
        try (FileWriter fw = new FileWriter(f.toFile())) {
            fw.write(PASS_RULE + "\n");
        }
        try (Waf waf = new Waf.Builder().rulesFile(f.toString()).build()) {
            assertTrue(waf.getRulesCount() >= 1);
        }
    }

    @Test
    void testBuilderWithInvalidRulesFileThrows() {
        // Missing file is detected at build() time.
        assertThrows(CorazaException.class, () ->
            new Waf.Builder().rulesFile("/nonexistent/path/rules.conf").build()
        );
    }

    @Test
    void testBuilderWithBadInlineRuleThrows() {
        // Invalid directive is detected at build() time.
        assertThrows(CorazaException.class, () ->
            new Waf.Builder().rule("this is not a valid SecRule").build()
        );
    }

    @Test
    void testBuilderNoRulesZeroCount() {
        try (Waf waf = new Waf.Builder().build()) {
            assertEquals(0, waf.getRulesCount());
        }
    }

    @Test
    void testBuilderIsFluent() {
        // Verify all builder methods return the builder for chaining.
        assertDoesNotThrow(() -> {
            try (Waf waf = new Waf.Builder()
                    .rule(DENY_RULE)
                    .onRuleMatch(h -> {})
                    .onDebugLog((l, m, f) -> {})
                    .build()) {
                assertTrue(waf.getRulesCount() >= 1);
            }
        });
    }

    // ------------------------------------------------------------------
    // Transaction via high-level API
    // ------------------------------------------------------------------

    @Test
    void testTransactionAutoCloseable() {
        try (Waf waf = new Waf.Builder().rule(PASS_RULE).build();
             Transaction tx = waf.newTransaction()) {
            assertEquals(0, tx.processConnection("10.0.0.1", 12345, "localhost", 80));
        }
    }

    @Test
    void testTransactionWithIdAutoCloseable() {
        try (Waf waf = new Waf.Builder().rule(PASS_RULE).build();
             Transaction tx = waf.newTransactionWithId("hl-tx-001")) {
            assertEquals(0, tx.processConnection("10.0.0.1", 12345, "localhost", 80));
        }
    }

    @Test
    void testTransactionFullLifecycleDeny() {
        try (Waf waf = new Waf.Builder().rule(DENY_RULE).build();
             Transaction tx = waf.newTransaction()) {

            assertEquals(0, tx.processConnection("127.0.0.1", 55555, "localhost", 80));
            assertEquals(0, tx.addRequestHeader("Host", "localhost"));
            assertEquals(0, tx.addGetArgs("q", "test"));
            assertEquals(0, tx.processUri("/search?q=test", "GET", "HTTP/1.1"));
            assertEquals(0, tx.processRequestHeaders());
            assertEquals(0, tx.appendRequestBody("body".getBytes()));
            assertEquals(0, tx.processRequestBody());
            assertEquals(0, tx.processResponseHeaders(200, "HTTP/1.1"));
            assertEquals(0, tx.addResponseHeader("Content-Type", "text/html"));
            assertEquals(0, tx.appendResponseBody("<html/>".getBytes()));
            assertEquals(0, tx.processResponseBody());
            tx.updateStatusCode(403);
            assertEquals(0, tx.processLogging());

            Optional<Intervention> maybeIt = tx.intervention();
            assertTrue(maybeIt.isPresent(), "expected an intervention");
            try (Intervention it = maybeIt.get()) {
                assertEquals(403, it.getStatus());
                assertEquals("deny", it.getAction());
                assertNull(it.getData());
            }
        }
    }

    @Test
    void testTransactionFullLifecyclePass() {
        try (Waf waf = new Waf.Builder().rule(PASS_RULE).build();
             Transaction tx = waf.newTransaction()) {

            assertEquals(0, tx.processConnection("10.0.0.1", 12345, "localhost", 80));
            assertEquals(0, tx.processUri("/ok", "GET", "HTTP/1.1"));
            assertEquals(0, tx.processRequestHeaders());
            assertEquals(0, tx.processResponseHeaders(200, "HTTP/1.1"));
            assertEquals(0, tx.processResponseBody());
            assertEquals(0, tx.processLogging());

            assertFalse(tx.intervention().isPresent(), "expected no intervention");
        }
    }

    @Test
    void testTransactionFreeIdempotent() {
        try (Waf waf = new Waf.Builder().rule(PASS_RULE).build()) {
            Transaction tx = waf.newTransaction();
            assertEquals(0, tx.free());
            assertEquals(0, tx.free());  // idempotent
        }
    }

    @Test
    void testTransactionRequestBodyFromFile(@TempDir Path tmp) throws IOException {
        Path body = tmp.resolve("body.txt");
        try (FileWriter fw = new FileWriter(body.toFile())) {
            fw.write("key=value");
        }
        try (Waf waf = new Waf.Builder().rule(PASS_RULE).build();
             Transaction tx = waf.newTransaction()) {
            tx.processConnection("10.0.0.1", 0, "localhost", 80);
            tx.processUri("/upload", "POST", "HTTP/1.1");
            tx.processRequestHeaders();
            assertEquals(0, tx.requestBodyFromFile(body.toString()));
        }
    }

    // ------------------------------------------------------------------
    // Intervention — Optional API
    // ------------------------------------------------------------------

    @Test
    void testInterventionRedirectOptional() {
        try (Waf waf = new Waf.Builder().rule(REDIRECT_RULE).build();
             Transaction tx = waf.newTransaction()) {

            tx.processConnection("10.0.0.1", 12345, "localhost", 80);
            tx.addGetArgs("trigger", "yes");
            tx.processUri("/?trigger=yes", "GET", "HTTP/1.1");
            tx.processRequestHeaders();

            Optional<Intervention> maybeIt = tx.intervention();
            assertTrue(maybeIt.isPresent());
            try (Intervention it = maybeIt.get()) {
                assertEquals(302, it.getStatus());
                assertEquals("redirect", it.getAction());
                assertEquals("http://example.com", it.getData());
            }
        }
    }

    @Test
    void testInterventionIfPresent() {
        List<Integer> statuses = new ArrayList<>();
        try (Waf waf = new Waf.Builder().rule(DENY_RULE).build();
             Transaction tx = waf.newTransaction()) {

            tx.processConnection("127.0.0.1", 12345, "localhost", 80);
            tx.processUri("/test", "GET", "HTTP/1.1");
            tx.processRequestHeaders();
            tx.processLogging();

            tx.intervention().ifPresent(it -> {
                try (it) {
                    statuses.add(it.getStatus());
                }
            });
        }
        assertFalse(statuses.isEmpty(), "callback should have fired");
        assertEquals(403, statuses.get(0));
    }

    @Test
    void testWafFreeIdempotent() {
        Waf waf = new Waf.Builder().rule(PASS_RULE).build();
        assertEquals(0, waf.free());
        assertEquals(0, waf.free());  // idempotent
    }

    // ------------------------------------------------------------------
    // Callbacks via Builder
    // ------------------------------------------------------------------

    @Test
    void testOnRuleMatchCallback() {
        List<Long> matched = new ArrayList<>();

        try (Waf waf = new Waf.Builder()
                .rule(DENY_RULE)
                .onRuleMatch(matched::add)
                .build();
             Transaction tx = waf.newTransaction()) {

            tx.processConnection("127.0.0.1", 12345, "localhost", 80);
            tx.processUri("/test", "GET", "HTTP/1.1");
            tx.processRequestHeaders();
            tx.processLogging();
        }

        assertFalse(matched.isEmpty(), "onRuleMatch callback should have fired");
    }

    @Test
    void testOnDebugLogCallback() {
        List<String> msgs = new ArrayList<>();

        try (Waf waf = new Waf.Builder()
                .rule(DENY_RULE)
                .onDebugLog((level, message, fields) -> msgs.add(message))
                .build()) {
            // Callback registered — message count depends on Coraza's log level.
            // We only verify registration did not throw.
        }
    }
}
