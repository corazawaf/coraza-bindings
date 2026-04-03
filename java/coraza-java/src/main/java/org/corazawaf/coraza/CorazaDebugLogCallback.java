package org.corazawaf.coraza;

/**
 * Callback for Coraza internal debug log messages.
 *
 * <p>Register via {@link Waf.Builder#onDebugLog(CorazaDebugLogCallback)}.
 * The callback is invoked from a native thread — keep implementations
 * short and thread-safe.
 *
 * <p>The volume of messages depends on Coraza's internal log level
 * (default: {@code ERROR}).  Expect verbose output when Coraza is compiled
 * with debug logging enabled.
 *
 * <pre>{@code
 * Waf waf = new Waf.Builder()
 *     .rule("SecRule ...")
 *     .onDebugLog((level, message, fields) ->
 *         logger.debug("[coraza level={}] {} {}", level, message, fields))
 *     .build();
 * }</pre>
 *
 * @see Waf.Builder#onDebugLog(CorazaDebugLogCallback)
 */
@FunctionalInterface
public interface CorazaDebugLogCallback {

    /**
     * Called for each debug log message emitted by Coraza.
     *
     * @param level   numeric log level (maps to {@code coraza_log_level})
     * @param message the log message text
     * @param fields  structured key-value fields (may be empty, never {@code null})
     */
    void onDebugLog(int level, String message, String fields);
}
