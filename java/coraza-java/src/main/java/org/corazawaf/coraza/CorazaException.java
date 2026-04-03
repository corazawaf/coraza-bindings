package org.corazawaf.coraza;

/**
 * Thrown when the Coraza WAF engine reports an error.
 *
 * <p>This is an unchecked exception wrapping errors from the native layer so
 * callers can distinguish Coraza-specific failures from other
 * {@link RuntimeException} causes.
 *
 * <p>Common causes:
 * <ul>
 *   <li>A rules file path passed to {@link Waf.Builder#rulesFile} does not exist</li>
 *   <li>An inline rule passed to {@link Waf.Builder#rule} is syntactically invalid</li>
 *   <li>The native JNI library could not be loaded</li>
 * </ul>
 *
 * <p>Example:
 * <pre>{@code
 * try {
 *     Waf waf = new Waf.Builder().rulesFile("/missing/rules.conf").build();
 * } catch (CorazaException e) {
 *     logger.error("WAF configuration error: {}", e.getMessage());
 * }
 * }</pre>
 */
public class CorazaException extends RuntimeException {

    /**
     * Constructs a new {@code CorazaException} with the given detail message.
     *
     * @param message human-readable description of the error
     */
    public CorazaException(String message) {
        super(message);
    }

    /**
     * Constructs a new {@code CorazaException} wrapping an underlying cause.
     *
     * @param message human-readable description of the error
     * @param cause   the underlying exception
     */
    public CorazaException(String message, Throwable cause) {
        super(message, cause);
    }
}
