// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

package main

import "unsafe"

// jsOnError is provided by the JS host. It fires when a rule matches and the
// WAF was configured with coraza_set_error_callback.
//
// wafHandle — handle of the WAF that owns the matching transaction.
// msgPtr/msgLen — UTF-8 encoded ErrorLog() string in WASM linear memory.
//
//go:wasmimport coraza onError
func jsOnError(wafHandle int32, msgPtr unsafe.Pointer, msgLen int32)

// jsOnDebugLog is provided by the JS host when coraza_set_debug_log_callback
// was called. Receives all log events from the WAF (level 1=error … 9=trace).
//
//go:wasmimport coraza onDebugLog
func jsOnDebugLog(wafHandle int32, level int32, msgPtr unsafe.Pointer, msgLen int32)
