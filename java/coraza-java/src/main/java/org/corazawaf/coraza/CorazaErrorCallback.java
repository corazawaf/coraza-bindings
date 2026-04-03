package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;

/**
 * Callback invoked each time a Coraza rule matches.
 *
 * <p>Register via {@link Waf.Builder#onRuleMatch(CorazaErrorCallback)}.
 * The callback is invoked from a native thread during rule evaluation —
 * keep implementations short and thread-safe.
 *
 * <p>Use the SWIG helper functions to extract details from the opaque handle:
 *
 * <pre>{@code
 * Waf waf = new Waf.Builder()
 *     .rule("SecRule ...")
 *     .onRuleMatch(handle -> {
 *         String log = coraza.coraza_matched_rule_get_error_log(handle);
 *         int severity = coraza.coraza_matched_rule_get_severity(handle).swigValue();
 *         logger.warn("[sev={}] {}", severity, log);
 *     })
 *     .build();
 * }</pre>
 *
 * @see Waf.Builder#onRuleMatch(CorazaErrorCallback)
 */
@FunctionalInterface
public interface CorazaErrorCallback {

    /**
     * Called when a rule matches.
     *
     * @param ruleHandle opaque native handle to the matched rule — pass to
     *                   {@link coraza#coraza_matched_rule_get_error_log} or
     *                   {@link coraza#coraza_matched_rule_get_severity} to read details
     */
    void onError(long ruleHandle);
}
