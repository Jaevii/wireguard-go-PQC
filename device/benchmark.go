/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"os"
)

// benchmarkWriter holds an open file for benchmark timing output.
// It is nil-safe: all methods check for a nil receiver or nil file,
// so the zero value is safe to use and simply discards all writes.
//
// Activated by setting WIREGUARD_BENCH_LOG=/path/to/file before starting
// the wireguard-go process. The file is opened with O_APPEND so concurrent
// goroutines can write safely — on Linux, writes under PIPE_BUF (4096 bytes)
// to an O_APPEND file are atomic, and our log lines are well under that limit.
type benchmarkWriter struct {
	f *os.File
}

// newBenchmarkWriter opens the file named by WIREGUARD_BENCH_LOG for appending.
// If the variable is unset or the open fails, a no-op writer is returned.
func newBenchmarkWriter() *benchmarkWriter {
	path := os.Getenv("WIREGUARD_BENCH_LOG")
	if path == "" {
		return &benchmarkWriter{}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Don't prevent the device from starting just because bench logging failed.
		return &benchmarkWriter{}
	}
	return &benchmarkWriter{f: f}
}

// emit writes a single formatted line to the bench log.
// It is a no-op if the writer was not activated.
func (bw *benchmarkWriter) emit(format string, args ...any) {
	if bw == nil || bw.f == nil {
		return
	}
	// Sprintf + WriteString: one syscall, under PIPE_BUF, therefore atomic.
	bw.f.WriteString(fmt.Sprintf(format+"\n", args...))
}

// close releases the underlying file. Safe to call on a no-op writer.
func (bw *benchmarkWriter) close() {
	if bw != nil && bw.f != nil {
		bw.f.Close()
	}
}

// benchmarkEmit is the device-level helper called from instrumented code paths.
// It delegates to the device's benchmarkWriter, which is a no-op when
// WIREGUARD_BENCH_LOG is not set, adding no overhead in production.
func (device *Device) benchmarkEmit(format string, args ...any) {
	device.bench.emit(format, args...)
}
