package org.corazawaf.coraza;

import org.corazawaf.coraza.internal.swig.coraza;
import org.corazawaf.coraza.internal.swig.coraza_intervention_t;

import java.util.Optional;

/**
 * Represents a single HTTP transaction evaluated by the WAF.
 *
 * <p>Obtain instances via {@link Waf#newTransaction()} or
 * {@link Waf#newTransactionWithId(String)}.
 *
 * <p>The transaction lifecycle follows the Coraza processing phases in order:
 * <ol>
 *   <li>{@link #processConnection}</li>
 *   <li>{@link #processUri}</li>
 *   <li>{@link #addRequestHeader} / {@link #addGetArgs} (optional, before headers)</li>
 *   <li>{@link #processRequestHeaders}</li>
 *   <li>{@link #appendRequestBody} / {@link #requestBodyFromFile} (optional)</li>
 *   <li>{@link #processRequestBody}</li>
 *   <li>{@link #processResponseHeaders}</li>
 *   <li>{@link #addResponseHeader} (optional)</li>
 *   <li>{@link #appendResponseBody} (optional)</li>
 *   <li>{@link #processResponseBody}</li>
 *   <li>{@link #processLogging}</li>
 *   <li>{@link #intervention()} — inspect <em>after</em> the relevant phase</li>
 * </ol>
 *
 * <p>All {@code process*()} and {@code add*()} methods return {@code 0} on success.
 *
 * <p><strong>Thread safety:</strong> a single {@code Transaction} must not be
 * shared across threads.
 *
 * <p><strong>Usage example:</strong>
 * <pre>{@code
 * try (Transaction tx = waf.newTransaction()) {
 *     tx.processConnection("1.2.3.4", 12345, "app.example.com", 443);
 *     tx.processUri("/api/v1/users", "POST", "HTTP/1.1");
 *     tx.addRequestHeader("Content-Type", "application/json");
 *     tx.processRequestHeaders();
 *     tx.appendRequestBody(bodyBytes);
 *     tx.processRequestBody();
 *     tx.processLogging();
 *
 *     Optional<Intervention> it = tx.intervention();
 *     if (it.isPresent()) {
 *         try (Intervention intervention = it.get()) {
 *             return Response.status(intervention.getStatus()).build();
 *         }
 *     }
 * }
 * }</pre>
 */
public final class Transaction implements AutoCloseable {

    private final long tx;
    private boolean freed;

    Transaction(long tx) {
        this.tx = tx;
    }

    // ------------------------------------------------------------------
    // Connection / URI
    // ------------------------------------------------------------------

    /**
     * Records client/server connection metadata.
     *
     * <p>Must be called before {@link #processUri}.
     *
     * @param clientIp   client IP address (IPv4 or IPv6 string)
     * @param clientPort client TCP port
     * @param serverIp   server IP address or hostname
     * @param serverPort server TCP port
     * @return 0 on success
     */
    public int processConnection(
            String clientIp, int clientPort, String serverIp, int serverPort) {
        return coraza.coraza_process_connection(tx, clientIp, clientPort, serverIp, serverPort);
    }

    /**
     * Records the request URI, HTTP method, and protocol version.
     *
     * @param uri         full request URI (may include query string)
     * @param method      HTTP method (e.g. {@code "GET"}, {@code "POST"})
     * @param httpVersion protocol version string (e.g. {@code "HTTP/1.1"})
     * @return 0 on success
     */
    public int processUri(String uri, String method, String httpVersion) {
        return coraza.coraza_process_uri(tx, uri, method, httpVersion);
    }

    // ------------------------------------------------------------------
    // Request headers / query args
    // ------------------------------------------------------------------

    /**
     * Adds a single request header.
     *
     * <p>Call before {@link #processRequestHeaders}.
     *
     * @param name  header name
     * @param value header value
     * @return 0 on success
     */
    public int addRequestHeader(String name, String value) {
        return coraza.coraza_add_request_header(tx, name, name.length(), value, value.length());
    }

    /**
     * Adds a single query-string argument.
     *
     * <p>Can be called before or after {@link #processUri}.
     *
     * @param name  argument name
     * @param value argument value
     * @return 0 on success
     */
    public int addGetArgs(String name, String value) {
        return coraza.coraza_add_get_args(tx, name, value);
    }

    /**
     * Signals that all request headers have been added and runs phase-1 rules.
     *
     * @return 0 on success
     */
    public int processRequestHeaders() {
        return coraza.coraza_process_request_headers(tx);
    }

    // ------------------------------------------------------------------
    // Request body
    // ------------------------------------------------------------------

    /**
     * Appends a chunk of the request body.
     *
     * <p>Call {@link #processRequestBody()} after the last chunk.
     *
     * @param data raw body bytes
     * @return 0 on success
     */
    public int appendRequestBody(byte[] data) {
        return coraza.coraza_append_request_body(tx, data);
    }

    /**
     * Signals end-of-request-body and runs phase-2 rules.
     *
     * @return 0 on success
     */
    public int processRequestBody() {
        return coraza.coraza_process_request_body(tx);
    }

    /**
     * Loads the request body from a file on disk.
     *
     * <p>Useful for large uploads already spooled to a temporary file.
     *
     * @param path absolute path to the body file
     * @return 0 on success
     */
    public int requestBodyFromFile(String path) {
        return coraza.coraza_request_body_from_file(tx, path);
    }

    // ------------------------------------------------------------------
    // Response
    // ------------------------------------------------------------------

    /**
     * Records the upstream response status and runs phase-3 rules.
     *
     * @param status      HTTP status code from the upstream response
     * @param httpVersion protocol version string (e.g. {@code "HTTP/1.1"})
     * @return 0 on success
     */
    public int processResponseHeaders(int status, String httpVersion) {
        return coraza.coraza_process_response_headers(tx, status, httpVersion);
    }

    /**
     * Adds a single response header.
     *
     * @param name  header name
     * @param value header value
     * @return 0 on success
     */
    public int addResponseHeader(String name, String value) {
        return coraza.coraza_add_response_header(tx, name, name.length(), value, value.length());
    }

    /**
     * Appends a chunk of the response body.
     *
     * @param data raw body bytes
     * @return 0 on success
     */
    public int appendResponseBody(byte[] data) {
        return coraza.coraza_append_response_body(tx, data);
    }

    /**
     * Signals end-of-response-body and runs phase-4 rules.
     *
     * @return 0 on success
     */
    public int processResponseBody() {
        return coraza.coraza_process_response_body(tx);
    }

    /**
     * Updates the HTTP status code after the response has been processed.
     *
     * @param status new HTTP status code
     */
    public void updateStatusCode(int status) {
        coraza.coraza_update_status_code(tx, status);
    }

    // ------------------------------------------------------------------
    // Finalization
    // ------------------------------------------------------------------

    /**
     * Runs phase-5 (logging) rules and flushes the audit log.
     *
     * <p>Always call this before {@link #intervention()} and before {@link #free()}.
     *
     * @return 0 on success
     */
    public int processLogging() {
        return coraza.coraza_process_logging(tx);
    }

    /**
     * Returns the current WAF intervention wrapped in an {@link Optional}.
     *
     * <p>Returns {@link Optional#empty()} when no rule matched.  When present,
     * the {@link Intervention} <strong>must</strong> be closed after use to
     * release native memory:
     *
     * <pre>{@code
     * tx.intervention().ifPresent(it -> {
     *     try (it) {
     *         response.setStatus(it.getStatus());
     *     }
     * });
     * }</pre>
     *
     * @return an {@code Optional} containing the intervention, or empty
     */
    public Optional<Intervention> intervention() {
        coraza_intervention_t raw = coraza.coraza_intervention(tx);
        return Optional.ofNullable(raw).map(Intervention::new);
    }

    /**
     * Releases the transaction.  Idempotent — safe to call multiple times.
     *
     * @return 0 on success
     */
    public int free() {
        if (freed) return 0;
        freed = true;
        return coraza.coraza_free_transaction(tx);
    }

    /** Calls {@link #free()}. */
    @Override
    public void close() {
        free();
    }
}
