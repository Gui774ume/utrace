/*
Copyright © 2021 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package run

import (
	"github.com/spf13/cobra"
)

// Utrace represents the base command of utrace
var Utrace = &cobra.Command{
	Use:  "utrace",
	RunE: utraceCmd,
}

var options CLIOptions

func init() {
	Utrace.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		`log level, options: panic, fatal, error, warn, info, debug or trace`)
	Utrace.Flags().BoolVarP(
		&options.GenerateGraph,
		"generate-graph",
		"g",
		false,
		`when set, utrace will generate a .dot graph with the collected statistics`)
	Utrace.Flags().VarP(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "executable"),
		"executable",
		"e",
		`list of paths to the executables you want to trace`)
	Utrace.Flags().VarP(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "pattern"),
		"pattern",
		"p",
		`user space function(s) pattern to trace, optionally prefixed with a path to binary containing these functions (eg. '/lib/x86_64-linux-gnu/libc.so.6:malloc')`)
	Utrace.Flags().VarP(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "kernel-pattern"),
		"kernel-pattern",
		"k",
		`kernel space function(s) pattern to trace`)
	Utrace.Flags().BoolVarP(
		&options.UTraceOptions.Latency,
		"latency",
		"t",
		false,
		`when set, utrace will use uprobes to compute functions latency`)
	Utrace.Flags().BoolVarP(
		&options.UTraceOptions.StackTraces,
		"stack-traces",
		"s",
		false,
		`when set, utrace will use uprobes to collect functions stack traces`)
	Utrace.Flags().Var(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "pid"),
		"pid",
		`list of pids to trace. Leave empty to disable filtering`)
	Utrace.Flags().Var(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "tracepoint"),
		"tracepoint",
		`list of tracepoints to trace. Expected format: [category]:[name]`)
	Utrace.Flags().Var(
		NewUTraceOptionsSanitizer(&options.UTraceOptions, "perf"),
		"perf",
		`list of perf events to trace. Expected format: [perf_event_type]:[perf_event_name]:[frequency], where perf_event_type, perf_event_name and frequency are numbers. For example, add '1:1:1' to trace PERF_COUNT_SW_TASK_CLOCK from the PERF_TYPE_SOFTWARE perf events at a frequency of 1 event per second`)
}
