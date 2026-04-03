package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.NativeLoader;
import org.corazawaf.coraza.internal.swig.coraza;

/**
 * A compiled Coraza WAF instance holding a set of loaded rules.
 *
 * <p>Use {@link Builder} to configure and create a {@code Waf}:
 *
 * <pre>{@code
 * try (Waf waf = new Waf.Builder()
 *         .rule("SecRuleEngine On")
 *         .rule("SecRule REQUEST_URI \"@contains /admin\" "
 *             + "\"id:1,phase:1,deny,status:403\"")
 *         .onRuleMatch(h -> logger.warn("Rule matched: {}", h))
 *         .build()) {
 *
 *     try (Transaction tx = waf.newTransaction()) {
 *         tx.processConnection("1.2.3.4", 12345, "app.example.com", 443);
 *         tx.processUri("/admin", "GET", "HTTP/1.1");
 *         tx.processRequestHeaders();
 *         tx.processLogging();
 *
 *         tx.intervention().ifPresent(it -> {
 *             try (it) {
 *                 System.out.printf("Blocked: %d %s%n",
 *                     it.getStatus(), it.getAction());
 *             }
 *         });
 *     }
 * }
 * }</pre>
 *
 * <p><strong>Thread safety:</strong> a single {@code Waf} instance is safe to
 * share across threads.  Each thread must use its own {@link Transaction}.
 */
public final class Waf implements AutoCloseable {

    static {
        NativeLoader.load();
    }

    private final long waf;
    private boolean freed;

    private Waf(long waf) {
        this.waf = waf;
    }

    // ------------------------------------------------------------------
    // Transactions
    // ------------------------------------------------------------------

    /**
     * Creates a new transaction for processing a single HTTP request/response.
     *
     * <p>Each request must use its own transaction.  Transactions are
     * <strong>not</strong> thread-safe — do not share a transaction across threads.
     *
     * @return a new {@link Transaction}; caller must close it when done
     */
    public Transaction newTransaction() {
        return new Transaction(coraza.coraza_new_transaction(waf));
    }

    /**
     * Creates a new transaction with a caller-supplied correlation ID.
     *
     * <p>The {@code txId} appears in Coraza audit log entries, making it
     * easier to correlate WAF events with application request logs.
     *
     * @param txId unique identifier for this transaction (e.g. a request UUID)
     * @return a new {@link Transaction}; caller must close it when done
     */
    public Transaction newTransactionWithId(String txId) {
        return new Transaction(coraza.coraza_new_transaction_with_id(waf, txId));
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /**
     * Returns the total number of rules loaded into this WAF instance.
     *
     * @return rule count (&ge; 0)
     */
    public int getRulesCount() {
        return coraza.coraza_rules_count(waf);
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /**
     * Releases the WAF.  Idempotent — safe to call multiple times.
     *
     * @return 0 on success
     */
    public int free() {
        if (freed) return 0;
        freed = true;
        return coraza.coraza_free_waf(waf);
    }

    /** Calls {@link #free()}. */
    @Override
    public void close() {
        free();
    }

    // ------------------------------------------------------------------
    // Builder
    // ------------------------------------------------------------------

    /**
     * Fluent builder for {@link Waf}.
     *
     * <p>Rules are applied in the order they are added.  The builder may be
     * reused to create multiple independent WAF instances.
     *
     * <pre>{@code
     * Waf waf = new Waf.Builder()
     *     .rulesFile("/etc/coraza/crs-setup.conf")
     *     .rulesFile("/etc/coraza/rules/*.conf")
     *     .onRuleMatch(handle -> auditLog.record(handle))
     *     .build();
     * }</pre>
     */
    public static final class Builder {

        private final long cfg;

        /** Creates a new builder with an empty configuration. */
        public Builder() {
            cfg = coraza.coraza_new_waf_config();
        }

        /**
         * Adds an inline SecRule directive string.
         *
         * <p>Note: Coraza does not validate rule syntax at add time — invalid
         * rules cause a {@link CorazaException} only when {@link #build()} is called.
         *
         * @param rule a valid SecRule directive
         * @return this builder, for chaining
         * @throws CorazaException if the underlying C call fails unexpectedly
         */
        public Builder rule(String rule) {
            int ret = coraza.coraza_rules_add(cfg, rule);
            if (ret != 0) {
                throw new CorazaException("coraza_rules_add failed (ret=" + ret + ")");
            }
            return this;
        }

        /**
         * Adds rules from a file path (or glob pattern, if supported by Coraza).
         *
         * <p>Note: missing files are not reported until {@link #build()} is called.
         *
         * @param path absolute path to a Coraza rules file
         * @return this builder, for chaining
         * @throws CorazaException if the underlying C call fails unexpectedly
         */
        public Builder rulesFile(String path) {
            int ret = coraza.coraza_rules_add_file(cfg, path);
            if (ret != 0) {
                throw new CorazaException("coraza_rules_add_file failed (ret=" + ret + ")");
            }
            return this;
        }

        /**
         * Registers a callback invoked each time a rule matches.
         *
         * <p>The callback receives an opaque rule handle.  Use
         * {@code coraza.coraza_matched_rule_get_error_log(handle)} and
         * {@code coraza.coraza_matched_rule_get_severity(handle)} to extract
         * details.  Callbacks are invoked from a native thread — keep them
         * short and thread-safe.
         *
         * @param callback the error callback; must not be {@code null}
         * @return this builder, for chaining
         * @throws CorazaException if registration fails
         */
        public Builder onRuleMatch(CorazaErrorCallback callback) {
            int ret = coraza.coraza_set_error_callback(cfg, callback);
            if (ret != 0) {
                throw new CorazaException(
                        "coraza_set_error_callback failed (ret=" + ret + ")");
            }
            return this;
        }

        /**
         * Registers a callback for Coraza internal debug log messages.
         *
         * <p>Message volume depends on Coraza's internal log level
         * (default: {@code ERROR}).  Callbacks are invoked from a native
         * thread — keep them short and thread-safe.
         *
         * @param callback the debug log callback; must not be {@code null}
         * @return this builder, for chaining
         * @throws CorazaException if registration fails
         */
        public Builder onDebugLog(CorazaDebugLogCallback callback) {
            int ret = coraza.coraza_set_debug_log_callback(cfg, callback);
            if (ret != 0) {
                throw new CorazaException(
                        "coraza_set_debug_log_callback failed (ret=" + ret + ")");
            }
            return this;
        }

        /**
         * Builds the {@link Waf} instance.
         *
         * <p>The configuration handle is consumed — do not use this builder
         * after calling {@code build()}.
         *
         * @return a ready-to-use {@link Waf}
         * @throws CorazaException if the WAF cannot be initialised (e.g. a
         *                         rules file is missing or a rule is invalid)
         */
        public Waf build() {
            try {
                long wafHandle = coraza.coraza_new_waf(cfg);
                return new Waf(wafHandle);
            } catch (RuntimeException e) {
                throw new CorazaException("Failed to create WAF: " + e.getMessage(), e);
            } finally {
                coraza.coraza_free_waf_config(cfg);
            }
        }
    }
}
