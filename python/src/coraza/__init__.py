"""
OWASP Coraza WAF — Python bindings.

High-level API (preferred)
--------------------------
    from coraza import Waf, Transaction, Intervention, CorazaException

    with Waf.from_rules(
        'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:1,phase:1,deny,status:403"'
    ) as waf:
        with waf.new_transaction() as tx:
            tx.process_connection("1.2.3.4", 12345, "localhost", 80)
            tx.process_uri("/path", "GET", "HTTP/1.1")
            tx.process_request_headers()
            tx.process_logging()

            it = tx.intervention()
            if it is not None:
                with it:
                    print(f"Blocked: {it.status} {it.action}")

Low-level SWIG functions
------------------------
All ``coraza_*`` symbols from the SWIG layer are re-exported directly for
users who need raw access or are migrating from C:

    from coraza import coraza_new_waf_config, coraza_rules_add, ...

Code style
----------
- Use context managers (``with`` statement) for all WAF, transaction, and
  intervention objects to guarantee native memory is released.
- Prefer ``Waf.from_rules()`` or ``Waf.from_config()`` over the SWIG layer.
- Always call ``tx.process_logging()`` before inspecting interventions.
- ``intervention()`` returns ``None`` when no rule matched — always check.
- Callbacks must be plain callables (functions, lambdas, or objects with
  ``__call__``). They are called from a native thread; keep them short and
  thread-safe.
"""

from __future__ import annotations

from typing import Callable, Optional

from ._version import __version__
from ._coraza_swig import (  # noqa: F401 — re-export all raw SWIG symbols
    coraza_new_waf_config,
    coraza_rules_add,
    coraza_rules_add_file,
    coraza_new_waf,
    coraza_rules_count,
    coraza_rules_merge,
    coraza_free_waf_config,
    coraza_free_waf,
    coraza_new_transaction,
    coraza_new_transaction_with_id,
    coraza_free_transaction,
    coraza_process_connection,
    coraza_process_uri,
    coraza_add_request_header,
    coraza_add_get_args,
    coraza_process_request_headers,
    coraza_append_request_body,
    coraza_process_request_body,
    coraza_request_body_from_file,
    coraza_process_response_headers,
    coraza_add_response_header,
    coraza_append_response_body,
    coraza_process_response_body,
    coraza_update_status_code,
    coraza_process_logging,
    coraza_intervention,
    coraza_free_intervention,
    coraza_set_error_callback,
    coraza_set_debug_log_callback,
    coraza_matched_rule_get_error_log,
    coraza_matched_rule_get_severity,
    coraza_intervention_t,
    # Debug log level constants
    CORAZA_DEBUG_LOG_LEVEL_UNKNOWN,
    CORAZA_DEBUG_LOG_LEVEL_TRACE,
    CORAZA_DEBUG_LOG_LEVEL_DEBUG,
    CORAZA_DEBUG_LOG_LEVEL_INFO,
    CORAZA_DEBUG_LOG_LEVEL_WARN,
    CORAZA_DEBUG_LOG_LEVEL_ERROR,
    # Severity constants
    CORAZA_SEVERITY_UNKNOWN,
    CORAZA_SEVERITY_EMERGENCY,
    CORAZA_SEVERITY_ALERT,
    CORAZA_SEVERITY_CRITICAL,
    CORAZA_SEVERITY_ERROR,
    CORAZA_SEVERITY_WARNING,
    CORAZA_SEVERITY_NOTICE,
    CORAZA_SEVERITY_INFO,
    CORAZA_SEVERITY_DEBUG,
)

__all__ = [
    "__version__",
    "CorazaException",
    "Waf",
    "Transaction",
    "Intervention",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CorazaException(RuntimeError):
    """Raised when the Coraza WAF engine reports an error.

    Wraps the underlying ``RuntimeError`` from the SWIG/C layer so callers
    can catch Coraza-specific errors without catching every ``RuntimeError``
    in the program.

    Example::

        try:
            waf = Waf.from_rules("bad rule")
        except CorazaException as exc:
            logger.error("WAF config invalid: %s", exc)
    """


# ---------------------------------------------------------------------------
# Intervention
# ---------------------------------------------------------------------------

class Intervention:
    """Wraps a matched-rule intervention returned by :meth:`Transaction.intervention`.

    An intervention signals that the WAF wants to block, redirect, or otherwise
    interrupt the request/response lifecycle.  Always use as a context manager
    or call :meth:`free` explicitly to release native memory.

    Attributes
    ----------
    status : int
        HTTP status code to return to the client (e.g. ``403``, ``302``).
    action : str
        Action string: ``"deny"``, ``"redirect"``, ``"drop"``, etc.
    data : str or None
        Auxiliary data — for redirect actions this is the target URL.

    Example::

        it = tx.intervention()
        if it is not None:
            with it:
                response.status_code = it.status
                if it.action == "redirect":
                    response.headers["Location"] = it.data
    """

    def __init__(self, raw: coraza_intervention_t) -> None:
        self._raw = raw

    @property
    def status(self) -> int:
        """HTTP status code dictated by the matched rule."""
        return self._raw.status

    @property
    def action(self) -> str:
        """Action string (e.g. ``"deny"``, ``"redirect"``)."""
        return self._raw.action

    @property
    def data(self) -> Optional[str]:
        """Auxiliary data from the matched rule, or ``None``.

        For redirect rules this contains the target URL.
        """
        return self._raw.data or None

    def free(self) -> int:
        """Release the native intervention struct.

        Returns 0 on success.  Calling :meth:`free` more than once on the
        same object is **undefined behaviour** at the C layer — use the
        context manager instead to guarantee a single release.
        """
        return coraza_free_intervention(self._raw)

    def __enter__(self) -> "Intervention":
        return self

    def __exit__(self, *_: object) -> None:
        self.free()

    def __repr__(self) -> str:
        return (
            f"Intervention(status={self.status!r}, "
            f"action={self.action!r}, data={self.data!r})"
        )


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------

class Transaction:
    """Represents a single HTTP transaction evaluated by the WAF.

    Obtain instances via :meth:`Waf.new_transaction` or
    :meth:`Waf.new_transaction_with_id`.  Always use as a context manager
    or call :meth:`free` explicitly.

    The transaction lifecycle follows the Coraza processing phases in order:

    1. :meth:`process_connection`
    2. :meth:`process_uri`
    3. :meth:`add_request_header` / :meth:`add_get_args` (optional, before headers)
    4. :meth:`process_request_headers`
    5. :meth:`append_request_body` / :meth:`request_body_from_file` (optional)
    6. :meth:`process_request_body`
    7. :meth:`process_response_headers`
    8. :meth:`add_response_header` (optional)
    9. :meth:`append_response_body` (optional)
    10. :meth:`process_response_body`
    11. :meth:`process_logging`
    12. :meth:`intervention` — inspect *after* the relevant phase

    All ``process_*`` and ``add_*`` methods return ``0`` on success.

    Example::

        with waf.new_transaction() as tx:
            tx.process_connection("1.2.3.4", 12345, "app.example.com", 443)
            tx.process_uri("/api/v1/users", "POST", "HTTP/1.1")
            tx.add_request_header("Content-Type", "application/json")
            tx.process_request_headers()
            tx.append_request_body(body_bytes)
            tx.process_request_body()

            it = tx.intervention()
            if it is not None:
                with it:
                    return HttpResponse(status=it.status)

            # proceed with upstream request ...
    """

    def __init__(self, handle: int) -> None:
        self._tx = handle
        self._freed = False

    # ------------------------------------------------------------------
    # Connection / URI
    # ------------------------------------------------------------------

    def process_connection(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
    ) -> int:
        """Record client/server connection metadata.

        Must be called before :meth:`process_uri`.
        """
        return coraza_process_connection(
            self._tx, client_ip, client_port, server_ip, server_port
        )

    def process_uri(self, uri: str, method: str, http_version: str) -> int:
        """Record the request URI, HTTP method, and protocol version."""
        return coraza_process_uri(self._tx, uri, method, http_version)

    # ------------------------------------------------------------------
    # Request headers / args
    # ------------------------------------------------------------------

    def add_request_header(self, name: str, value: str) -> int:
        """Add a single request header.

        Call before :meth:`process_request_headers`.
        """
        return coraza_add_request_header(
            self._tx, name, len(name.encode()), value, len(value.encode())
        )

    def add_get_args(self, name: str, value: str) -> int:
        """Add a single query-string argument.

        Can be called before or after :meth:`process_uri`.
        """
        return coraza_add_get_args(self._tx, name, value)

    def process_request_headers(self) -> int:
        """Signal that all request headers have been added and run phase-1 rules."""
        return coraza_process_request_headers(self._tx)

    # ------------------------------------------------------------------
    # Request body
    # ------------------------------------------------------------------

    def append_request_body(self, data: bytes) -> int:
        """Append a chunk of the request body.

        *data* must be :class:`bytes` or :class:`bytearray`.
        Call :meth:`process_request_body` after the last chunk.
        """
        return coraza_append_request_body(self._tx, data)

    def process_request_body(self) -> int:
        """Signal end-of-request-body and run phase-2 rules."""
        return coraza_process_request_body(self._tx)

    def request_body_from_file(self, path: str) -> int:
        """Load the request body from a file on disk.

        Useful for large uploads already spooled to a temp file.
        """
        return coraza_request_body_from_file(self._tx, path)

    # ------------------------------------------------------------------
    # Response headers
    # ------------------------------------------------------------------

    def process_response_headers(self, status: int, http_version: str) -> int:
        """Record the upstream response status and run phase-3 rules."""
        return coraza_process_response_headers(self._tx, status, http_version)

    def add_response_header(self, name: str, value: str) -> int:
        """Add a single response header.

        Call before :meth:`process_response_headers` (or immediately after,
        before :meth:`process_response_body`).
        """
        return coraza_add_response_header(
            self._tx, name, len(name.encode()), value, len(value.encode())
        )

    # ------------------------------------------------------------------
    # Response body
    # ------------------------------------------------------------------

    def append_response_body(self, data: bytes) -> int:
        """Append a chunk of the response body.

        *data* must be :class:`bytes` or :class:`bytearray`.
        """
        return coraza_append_response_body(self._tx, data)

    def process_response_body(self) -> int:
        """Signal end-of-response-body and run phase-4 rules."""
        return coraza_process_response_body(self._tx)

    def update_status_code(self, status: int) -> None:
        """Update the HTTP status code after the response has been processed."""
        coraza_update_status_code(self._tx, status)

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def process_logging(self) -> int:
        """Run phase-5 (logging) rules and flush audit log.

        Always call this before :meth:`intervention` and before :meth:`free`.
        """
        return coraza_process_logging(self._tx)

    def intervention(self) -> Optional[Intervention]:
        """Return the current intervention, or ``None`` if no rule matched.

        The returned :class:`Intervention` must be freed after use — prefer
        using it as a context manager::

            it = tx.intervention()
            if it is not None:
                with it:
                    response.status_code = it.status

        Returns
        -------
        Intervention or None
        """
        raw = coraza_intervention(self._tx)
        return Intervention(raw) if raw is not None else None

    def free(self) -> int:
        """Release the transaction.  Idempotent — safe to call multiple times."""
        if self._freed:
            return 0
        self._freed = True
        return coraza_free_transaction(self._tx)

    def __enter__(self) -> "Transaction":
        return self

    def __exit__(self, *_: object) -> None:
        self.free()

    def __repr__(self) -> str:
        return f"Transaction(handle={self._tx!r}, freed={self._freed!r})"


# ---------------------------------------------------------------------------
# Waf
# ---------------------------------------------------------------------------

class Waf:
    """A compiled Coraza WAF instance holding a set of loaded rules.

    **Thread safety**: a single :class:`Waf` instance is safe to share across
    threads.  Each thread must use its own :class:`Transaction`.

    Create via the factory class methods :meth:`from_rules` or
    :meth:`from_config`.  Always use as a context manager or call
    :meth:`free` explicitly::

        with Waf.from_rules(
            'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:1,phase:1,deny"'
        ) as waf:
            with waf.new_transaction() as tx:
                ...
    """

    def __init__(self, handle: int) -> None:
        self._waf = handle
        self._freed = False

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_rules(cls, *rules: str) -> "Waf":
        """Create a WAF from one or more inline SecRule directives.

        Parameters
        ----------
        *rules:
            One or more SecRule strings.  Rules are added in order.

        Raises
        ------
        CorazaException
            If any rule is syntactically invalid or the WAF cannot be
            initialised (e.g. a referenced file is missing).

        Example::

            waf = Waf.from_rules(
                'SecRuleEngine On',
                'SecRule REQUEST_URI "@contains /admin" "id:10,phase:1,deny"',
            )
        """
        cfg = coraza_new_waf_config()
        try:
            for rule in rules:
                coraza_rules_add(cfg, rule)
            waf = cls._create_waf(cfg)
        finally:
            coraza_free_waf_config(cfg)
        return waf

    @classmethod
    def from_config(
        cls,
        cfg: int,
        *,
        error_callback: Optional[Callable[[int], None]] = None,
        debug_callback: Optional[Callable[[int, str, str], None]] = None,
    ) -> "Waf":
        """Create a WAF from an already-populated config handle.

        Use this factory when you need full control over config construction
        (e.g. to add rules files) while still getting a managed :class:`Waf`.

        The ``cfg`` handle is **consumed** — do not use it after this call.

        Parameters
        ----------
        cfg:
            Raw config handle from :func:`coraza_new_waf_config`.
        error_callback:
            Optional callable invoked for each matched rule.
            Signature: ``(rule_handle: int) -> None``.
        debug_callback:
            Optional callable invoked for each debug log message.
            Signature: ``(level: int, message: str, fields: str) -> None``.

        Raises
        ------
        CorazaException
            If the WAF cannot be initialised.
        """
        if error_callback is not None:
            ret = coraza_set_error_callback(cfg, error_callback)
            if ret != 0:
                coraza_free_waf_config(cfg)
                raise CorazaException(
                    f"coraza_set_error_callback failed (ret={ret})"
                )
        if debug_callback is not None:
            ret = coraza_set_debug_log_callback(cfg, debug_callback)
            if ret != 0:
                coraza_free_waf_config(cfg)
                raise CorazaException(
                    f"coraza_set_debug_log_callback failed (ret={ret})"
                )
        try:
            return cls._create_waf(cfg)
        finally:
            coraza_free_waf_config(cfg)

    @classmethod
    def _create_waf(cls, cfg: int) -> "Waf":
        """Internal: call coraza_new_waf and wrap errors."""
        try:
            handle = coraza_new_waf(cfg)
        except RuntimeError as exc:
            raise CorazaException(str(exc)) from exc
        return cls(handle)

    # ------------------------------------------------------------------
    # Transactions
    # ------------------------------------------------------------------

    def new_transaction(self) -> Transaction:
        """Create a new transaction for processing a single HTTP request/response.

        Each request must use its own transaction.  Transactions are **not**
        thread-safe — do not share a transaction across threads.

        Returns
        -------
        Transaction
            Must be freed via context manager or explicit :meth:`Transaction.free`.
        """
        return Transaction(coraza_new_transaction(self._waf))

    def new_transaction_with_id(self, tx_id: str) -> Transaction:
        """Create a new transaction with a caller-supplied correlation ID.

        The *tx_id* appears in audit log entries, making it easier to
        correlate WAF events with your application's request logs.

        Parameters
        ----------
        tx_id:
            Unique string identifier for this transaction.
        """
        return Transaction(coraza_new_transaction_with_id(self._waf, tx_id))

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def rules_count(self) -> int:
        """Total number of rules loaded into this WAF instance."""
        return coraza_rules_count(self._waf)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def free(self) -> int:
        """Release the WAF.  Idempotent — safe to call multiple times."""
        if self._freed:
            return 0
        self._freed = True
        return coraza_free_waf(self._waf)

    def __enter__(self) -> "Waf":
        return self

    def __exit__(self, *_: object) -> None:
        self.free()

    def __repr__(self) -> str:
        return (
            f"Waf(handle={self._waf!r}, rules={coraza_rules_count(self._waf)!r}, "
            f"freed={self._freed!r})"
        )
