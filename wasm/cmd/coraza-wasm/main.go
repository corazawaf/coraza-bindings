// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0

// Package main is the WASM reactor module for coraza-wasm.
//
// There is intentionally no func main(). The absence of main() causes the Go
// compiler to emit a WASM reactor (exports _initialize instead of _start),
// so the host calls wasi.initialize(instance) once and then invokes exported
// functions at will.
//
// All exported functions follow the coraza C API naming convention.
// Handles (int32 IDs) are returned in place of pointers — Go objects are kept
// in in-process maps and never exposed to the host.
//
// String passing convention:
//
//   JS → Go  JS calls coraza_malloc(len), writes UTF-8 bytes, passes (ptr, len)
//            to the function, then calls coraza_free(ptr).
//
//   Go → JS  Go receives a caller-supplied (outPtr, maxLen) buffer, writes
//            bytes, returns the number of bytes written. -1 means "null" (e.g.
//            intervention.data when absent).

//go:build wasip1

package main

import (
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// main is intentionally empty. With -buildmode=c-shared the Go toolchain
// emits _initialize (reactor mode) instead of _start. The host calls
// wasi.initialize(instance) once; main() is never invoked.
func main() {}

// ---- Handle tables ----

var (
	cfgMu sync.Mutex
	cfgs  = make(map[int32]*cfgEntry)

	wafMu sync.Mutex
	wafs  = make(map[int32]coraza.WAF)

	txMu sync.Mutex
	txs  = make(map[int32]types.Transaction)

	itMu sync.Mutex
	its  = make(map[int32]*itSnapshot)

	// bufs prevents pinned allocations from being GC'd.
	bufMu sync.Mutex
	bufs  = make(map[uintptr][]byte)

	nextID atomic.Int32
)

type cfgEntry struct {
	config   coraza.WAFConfig
	hasErrCB bool
	hasDbgCB bool
}

type itSnapshot struct {
	status  int32
	action  string
	data    string
	hasData bool
}

func newID() int32 { return nextID.Add(1) }

// ---- String helpers ----

func readString(ptr unsafe.Pointer, length int32) string {
	if ptr == nil || length <= 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(ptr), length))
}

// writeString copies s into the caller-supplied WASM buffer and returns the
// number of bytes written. Returns the full length of s if outPtr is nil
// (useful for sizing queries). Returns -1 only on invalid handle.
func writeString(s string, outPtr unsafe.Pointer, maxLen int32) int32 {
	b := []byte(s)
	n := int32(len(b))
	if outPtr == nil || maxLen <= 0 {
		return n
	}
	if n > maxLen {
		n = maxLen
	}
	copy(unsafe.Slice((*byte)(outPtr), n), b[:n])
	return n
}

// ---- Memory management (for JS → Go string passing) ----

// coraza_malloc allocates size bytes of WASM linear memory and returns a
// pointer to it. The caller must pass the pointer to coraza_free when done.
//
//go:wasmexport coraza_malloc
func coraza_malloc(size int32) unsafe.Pointer {
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	ptr := unsafe.Pointer(&buf[0])
	bufMu.Lock()
	bufs[uintptr(ptr)] = buf
	bufMu.Unlock()
	return ptr
}

// coraza_free releases memory previously returned by coraza_malloc.
//
//go:wasmexport coraza_free
func coraza_free(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	bufMu.Lock()
	delete(bufs, uintptr(ptr))
	bufMu.Unlock()
}

// ---- WAF configuration ----

// coraza_new_waf_config creates a new WAF configuration handle.
// Request and response body access are enabled by default.
//
//go:wasmexport coraza_new_waf_config
func coraza_new_waf_config() int32 {
	id := newID()
	cfgMu.Lock()
	cfgs[id] = &cfgEntry{
		config: coraza.NewWAFConfig().
			WithRequestBodyAccess().
			WithResponseBodyAccess(),
	}
	cfgMu.Unlock()
	return id
}

// coraza_rules_add appends inline SecLang directives to the configuration.
// Returns 0 on success, -1 if the handle is unknown.
//
//go:wasmexport coraza_rules_add
func coraza_rules_add(cfgHandle int32, ptr unsafe.Pointer, length int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	rules := readString(ptr, length)
	cfgMu.Lock()
	entry, ok := cfgs[cfgHandle]
	if ok {
		entry.config = entry.config.WithDirectives(rules)
	}
	cfgMu.Unlock()
	if !ok {
		return -1
	}
	return 0
}

// coraza_rules_add_file appends rules from a filesystem path.
//
//go:wasmexport coraza_rules_add_file
func coraza_rules_add_file(cfgHandle int32, pathPtr unsafe.Pointer, pathLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	path := readString(pathPtr, pathLen)
	cfgMu.Lock()
	entry, ok := cfgs[cfgHandle]
	if ok {
		entry.config = entry.config.WithDirectivesFromFile(path)
	}
	cfgMu.Unlock()
	if !ok {
		return -1
	}
	return 0
}

// coraza_set_error_callback registers the JS onError import as the error
// callback for the WAF created from this config.
//
//go:wasmexport coraza_set_error_callback
func coraza_set_error_callback(cfgHandle int32) int32 {
	cfgMu.Lock()
	entry, ok := cfgs[cfgHandle]
	if ok {
		entry.hasErrCB = true
	}
	cfgMu.Unlock()
	if !ok {
		return -1
	}
	return 0
}

// coraza_set_debug_log_callback registers the JS onDebugLog import as the
// debug logger for the WAF created from this config.
//
//go:wasmexport coraza_set_debug_log_callback
func coraza_set_debug_log_callback(cfgHandle int32) int32 {
	cfgMu.Lock()
	entry, ok := cfgs[cfgHandle]
	if ok {
		entry.hasDbgCB = true
	}
	cfgMu.Unlock()
	if !ok {
		return -1
	}
	return 0
}

// coraza_new_waf creates a WAF from a configuration handle.
// Returns the WAF handle, or 0 on failure (bad config / rule parse error).
//
//go:wasmexport coraza_new_waf
func coraza_new_waf(cfgHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = 0
		}
	}()

	cfgMu.Lock()
	entry, ok := cfgs[cfgHandle]
	cfgMu.Unlock()
	if !ok {
		return 0
	}

	wafID := newID()
	cfg := entry.config

	if entry.hasErrCB {
		capturedID := wafID
		cfg = cfg.WithErrorCallback(func(rule types.MatchedRule) {
			msg := rule.ErrorLog()
			if len(msg) == 0 {
				return
			}
			b := []byte(msg)
			jsOnError(capturedID, unsafe.Pointer(&b[0]), int32(len(b)))
		})
	}

	if entry.hasDbgCB {
		cfg = cfg.WithDebugLogger(newDebugLogger(wafID))
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return 0
	}

	wafMu.Lock()
	wafs[wafID] = waf
	wafMu.Unlock()
	return wafID
}

func newDebugLogger(wafHandle int32) debuglog.Logger {
	return debuglog.DefaultWithPrinterFactory(func(_ io.Writer) debuglog.Printer {
		return func(lvl debuglog.Level, message, fields string) {
			var msg string
			if fields != "" {
				msg = message + " " + fields
			} else {
				msg = message
			}
			if len(msg) == 0 {
				return
			}
			b := []byte(msg)
			jsOnDebugLog(wafHandle, int32(lvl), unsafe.Pointer(&b[0]), int32(len(b)))
		}
	}).WithLevel(debuglog.LevelTrace)
}

// coraza_rules_count returns the number of rules loaded in this WAF.
//
//go:wasmexport coraza_rules_count
func coraza_rules_count(wafHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	wafMu.Lock()
	waf, ok := wafs[wafHandle]
	wafMu.Unlock()
	if !ok {
		return -1
	}
	if rw, ok := waf.(experimental.WAFWithRules); ok {
		return int32(rw.RulesCount())
	}
	return 0
}

// coraza_rules_merge is a stub. WAF merging is not supported in this binding.
// Returns 0 if both handles are valid.
//
//go:wasmexport coraza_rules_merge
func coraza_rules_merge(dstHandle int32, srcHandle int32) int32 {
	wafMu.Lock()
	_, dstOk := wafs[dstHandle]
	_, srcOk := wafs[srcHandle]
	wafMu.Unlock()
	if !dstOk || !srcOk {
		return -1
	}
	return 0
}

// coraza_free_waf_config releases the configuration handle.
//
//go:wasmexport coraza_free_waf_config
func coraza_free_waf_config(cfgHandle int32) {
	cfgMu.Lock()
	delete(cfgs, cfgHandle)
	cfgMu.Unlock()
}

// coraza_free_waf releases the WAF handle and closes the underlying instance.
//
//go:wasmexport coraza_free_waf
func coraza_free_waf(wafHandle int32) {
	wafMu.Lock()
	waf, ok := wafs[wafHandle]
	delete(wafs, wafHandle)
	wafMu.Unlock()
	if ok {
		if c, ok := waf.(io.Closer); ok {
			_ = c.Close()
		}
	}
}

// ---- Transactions ----

// coraza_new_transaction creates a new transaction from a WAF handle.
// Returns the transaction handle, or 0 on error.
//
//go:wasmexport coraza_new_transaction
func coraza_new_transaction(wafHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = 0
		}
	}()
	wafMu.Lock()
	waf, ok := wafs[wafHandle]
	wafMu.Unlock()
	if !ok {
		return 0
	}
	tx := waf.NewTransaction()
	id := newID()
	txMu.Lock()
	txs[id] = tx
	txMu.Unlock()
	return id
}

// coraza_new_transaction_with_id creates a transaction with a caller-supplied ID.
//
//go:wasmexport coraza_new_transaction_with_id
func coraza_new_transaction_with_id(wafHandle int32, idPtr unsafe.Pointer, idLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = 0
		}
	}()
	wafMu.Lock()
	waf, ok := wafs[wafHandle]
	wafMu.Unlock()
	if !ok {
		return 0
	}
	txID := readString(idPtr, idLen)
	tx := waf.NewTransactionWithID(txID)
	handle := newID()
	txMu.Lock()
	txs[handle] = tx
	txMu.Unlock()
	return handle
}

// coraza_process_connection records the TCP connection details.
// Returns 0 on success, -1 on unknown handle.
//
//go:wasmexport coraza_process_connection
func coraza_process_connection(txHandle int32, clientPtr unsafe.Pointer, clientLen int32, clientPort int32, serverPtr unsafe.Pointer, serverLen int32, serverPort int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.ProcessConnection(
		readString(clientPtr, clientLen), int(clientPort),
		readString(serverPtr, serverLen), int(serverPort),
	)
	return 0
}

// coraza_process_uri records the request URI, method, and HTTP version.
//
//go:wasmexport coraza_process_uri
func coraza_process_uri(txHandle int32, uriPtr unsafe.Pointer, uriLen int32, methodPtr unsafe.Pointer, methodLen int32, protoPtr unsafe.Pointer, protoLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.ProcessURI(
		readString(uriPtr, uriLen),
		readString(methodPtr, methodLen),
		readString(protoPtr, protoLen),
	)
	return 0
}

// coraza_add_request_header adds a single request header.
//
//go:wasmexport coraza_add_request_header
func coraza_add_request_header(txHandle int32, namePtr unsafe.Pointer, nameLen int32, valPtr unsafe.Pointer, valLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.AddRequestHeader(readString(namePtr, nameLen), readString(valPtr, valLen))
	return 0
}

// coraza_add_get_args adds a GET query-string argument.
//
//go:wasmexport coraza_add_get_args
func coraza_add_get_args(txHandle int32, namePtr unsafe.Pointer, nameLen int32, valPtr unsafe.Pointer, valLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.AddGetRequestArgument(readString(namePtr, nameLen), readString(valPtr, valLen))
	return 0
}

// coraza_process_request_headers evaluates request headers.
// Returns 0 = pass, 1 = interrupted, -1 = error.
//
//go:wasmexport coraza_process_request_headers
func coraza_process_request_headers(txHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return 1
	}
	return 0
}

// coraza_append_request_body writes a chunk of the request body.
// Returns 0 = pass, 1 = interrupted, -1 = error.
//
//go:wasmexport coraza_append_request_body
func coraza_append_request_body(txHandle int32, dataPtr unsafe.Pointer, dataLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	if dataPtr == nil || dataLen <= 0 {
		return 0
	}
	it, _, err := tx.WriteRequestBody(unsafe.Slice((*byte)(dataPtr), dataLen))
	if err != nil {
		return -1
	}
	if it != nil {
		return 1
	}
	return 0
}

// coraza_process_request_body evaluates the complete request body.
//
//go:wasmexport coraza_process_request_body
func coraza_process_request_body(txHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return -1
	}
	if it != nil {
		return 1
	}
	return 0
}

// coraza_request_body_from_file streams a file into the request body buffer.
//
//go:wasmexport coraza_request_body_from_file
func coraza_request_body_from_file(txHandle int32, pathPtr unsafe.Pointer, pathLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	path := readString(pathPtr, pathLen)
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	it, _, err := tx.ReadRequestBodyFrom(f)
	if err != nil {
		return -1
	}
	if it != nil {
		return 1
	}
	return 0
}

// coraza_process_response_headers evaluates response headers.
//
//go:wasmexport coraza_process_response_headers
func coraza_process_response_headers(txHandle int32, status int32, protoPtr unsafe.Pointer, protoLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	if it := tx.ProcessResponseHeaders(int(status), readString(protoPtr, protoLen)); it != nil {
		return 1
	}
	return 0
}

// coraza_add_response_header adds a single response header.
//
//go:wasmexport coraza_add_response_header
func coraza_add_response_header(txHandle int32, namePtr unsafe.Pointer, nameLen int32, valPtr unsafe.Pointer, valLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.AddResponseHeader(readString(namePtr, nameLen), readString(valPtr, valLen))
	return 0
}

// coraza_append_response_body writes a chunk of the response body.
//
//go:wasmexport coraza_append_response_body
func coraza_append_response_body(txHandle int32, dataPtr unsafe.Pointer, dataLen int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	if dataPtr == nil || dataLen <= 0 {
		return 0
	}
	it, _, err := tx.WriteResponseBody(unsafe.Slice((*byte)(dataPtr), dataLen))
	if err != nil {
		return -1
	}
	if it != nil {
		return 1
	}
	return 0
}

// coraza_process_response_body evaluates the complete response body.
//
//go:wasmexport coraza_process_response_body
func coraza_process_response_body(txHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	it, err := tx.ProcessResponseBody()
	if err != nil {
		return -1
	}
	if it != nil {
		return 1
	}
	return 0
}

// coraza_update_status_code updates the response status variable on the
// transaction. Used by reverse proxies to propagate the actual upstream status.
//
//go:wasmexport coraza_update_status_code
func coraza_update_status_code(txHandle int32, code int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	// TransactionState (experimental internal interface) exposes Variables().
	// The concrete type always implements it; we use a local interface to avoid
	// importing internal packages directly.
	type singleSetter interface{ Set(string) }
	if ts, ok := tx.(plugintypes.TransactionState); ok {
		if ss, ok := ts.Variables().ResponseStatus().(singleSetter); ok {
			ss.Set(strconv.Itoa(int(code)))
		}
	}
	return 0
}

// coraza_process_logging runs the logging phase and finalises the transaction.
// Must be called before coraza_free_transaction.
//
//go:wasmexport coraza_process_logging
func coraza_process_logging(txHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return -1
	}
	tx.ProcessLogging()
	return 0
}

// ---- Interventions ----

// coraza_intervention snapshots the current interruption into an intervention
// handle and returns it. Returns 0 if the transaction is not interrupted.
//
//go:wasmexport coraza_intervention
func coraza_intervention(txHandle int32) (result int32) {
	defer func() {
		if r := recover(); r != nil {
			result = 0
		}
	}()
	txMu.Lock()
	tx, ok := txs[txHandle]
	txMu.Unlock()
	if !ok {
		return 0
	}
	it := tx.Interruption()
	if it == nil {
		return 0
	}
	snap := &itSnapshot{
		status:  int32(it.Status),
		action:  it.Action,
		data:    it.Data,
		hasData: it.Data != "",
	}
	id := newID()
	itMu.Lock()
	its[id] = snap
	itMu.Unlock()
	return id
}

// coraza_intervention_get_status returns the HTTP status code of the
// intervention (typically 403 for deny).
//
//go:wasmexport coraza_intervention_get_status
func coraza_intervention_get_status(itHandle int32) int32 {
	itMu.Lock()
	snap, ok := its[itHandle]
	itMu.Unlock()
	if !ok {
		return -1
	}
	return snap.status
}

// coraza_intervention_get_action writes the action string ("deny", "redirect",
// "pass", …) into the caller-supplied buffer and returns the bytes written.
//
//go:wasmexport coraza_intervention_get_action
func coraza_intervention_get_action(itHandle int32, outPtr unsafe.Pointer, maxLen int32) int32 {
	itMu.Lock()
	snap, ok := its[itHandle]
	itMu.Unlock()
	if !ok {
		return -1
	}
	return writeString(snap.action, outPtr, maxLen)
}

// coraza_intervention_get_data writes the data field (redirect URL or empty)
// into the caller-supplied buffer. Returns -1 when the field is absent.
//
//go:wasmexport coraza_intervention_get_data
func coraza_intervention_get_data(itHandle int32, outPtr unsafe.Pointer, maxLen int32) int32 {
	itMu.Lock()
	snap, ok := its[itHandle]
	itMu.Unlock()
	if !ok {
		return -1
	}
	if !snap.hasData {
		return -1
	}
	return writeString(snap.data, outPtr, maxLen)
}

// coraza_free_intervention releases an intervention handle.
//
//go:wasmexport coraza_free_intervention
func coraza_free_intervention(itHandle int32) {
	itMu.Lock()
	delete(its, itHandle)
	itMu.Unlock()
}

// coraza_free_transaction runs ProcessLogging if not already called, then
// releases the transaction handle.
//
//go:wasmexport coraza_free_transaction
func coraza_free_transaction(txHandle int32) {
	txMu.Lock()
	tx, ok := txs[txHandle]
	delete(txs, txHandle)
	txMu.Unlock()
	if ok {
		_ = tx.Close()
	}
}
