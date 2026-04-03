package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.corazawaf.coraza.internal.swig.coraza_intervention_t;

/**
 * Represents a WAF intervention — a directive to block, redirect, or otherwise
 * alter the normal request/response lifecycle.
 *
 * <p>Obtain instances via {@link Transaction#intervention()}, which returns an
 * {@link java.util.Optional} wrapping an {@code Intervention}.
 *
 * <p>Native memory is held by this object.  Always close it after use,
 * preferably with try-with-resources:
 *
 * <pre>{@code
 * tx.intervention().ifPresent(it -> {
 *     try (it) {
 *         response.setStatus(it.getStatus());
 *         if ("redirect".equals(it.getAction())) {
 *             response.setHeader("Location", it.getData());
 *         }
 *     }
 * });
 * }</pre>
 */
public final class Intervention implements AutoCloseable {

    private final coraza_intervention_t raw;
    private boolean freed;

    Intervention(coraza_intervention_t raw) {
        this.raw = raw;
    }

    /**
     * Returns the HTTP status code the WAF wants to send to the client.
     *
     * <p>Common values: {@code 403} (deny/block), {@code 302} (redirect).
     *
     * @return HTTP status code
     */
    public int getStatus() {
        return raw.getStatus();
    }

    /**
     * Returns the action string from the matched rule.
     *
     * <p>Typical values: {@code "deny"}, {@code "redirect"}, {@code "drop"}.
     *
     * @return action string; never {@code null}
     */
    public String getAction() {
        return raw.getAction();
    }

    /**
     * Returns auxiliary data from the matched rule, or {@code null} if absent.
     *
     * <p>For redirect rules this is the destination URL.  For block/deny rules
     * this is typically {@code null} or an empty string.
     *
     * @return auxiliary data, or {@code null}
     */
    public String getData() {
        String data = raw.getData();
        return (data != null && !data.isEmpty()) ? data : null;
    }

    /**
     * Releases native memory held by this intervention.
     *
     * <p>Idempotent — subsequent calls are safe no-ops.
     */
    public void free() {
        if (!freed) {
            freed = true;
            coraza.coraza_free_intervention(raw);
        }
    }

    /** Calls {@link #free()}. */
    @Override
    public void close() {
        free();
    }

    @Override
    public String toString() {
        return "Intervention{status=" + raw.getStatus()
                + ", action='" + raw.getAction() + '\''
                + ", data='" + raw.getData() + '\''
                + '}';
    }
}
