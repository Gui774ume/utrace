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
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/utrace/pkg/utrace"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	LogLevel      logrus.Level
	GenerateGraph bool
	UTraceOptions utrace.Options
}

// LogLevelSanitizer is a log level sanitizer that ensures that the provided log level exists
type LogLevelSanitizer struct {
	logLevel *logrus.Level
}

// NewLogLevelSanitizer creates a new instance of LogLevelSanitizer. The sanitized level will be written in the provided
// logrus level
func NewLogLevelSanitizer(sanitizedLevel *logrus.Level) *LogLevelSanitizer {
	*sanitizedLevel = logrus.InfoLevel
	return &LogLevelSanitizer{
		logLevel: sanitizedLevel,
	}
}

func (lls *LogLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *lls.logLevel)
}

func (lls *LogLevelSanitizer) Set(val string) error {
	sanitized, err := logrus.ParseLevel(val)
	if err != nil {
		return err
	}
	*lls.logLevel = sanitized
	return nil
}

func (lls *LogLevelSanitizer) Type() string {
	return "string"
}

// UTraceOptionsSanitizer is a generic options sanitizer for UTrace
type UTraceOptionsSanitizer struct {
	field   string
	options *utrace.Options
}

// NewUTraceOptionsSanitizer creates a new instance of UTraceOptionsSanitizer
func NewUTraceOptionsSanitizer(options *utrace.Options, field string) *UTraceOptionsSanitizer {
	return &UTraceOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (uos *UTraceOptionsSanitizer) String() string {
	switch uos.field {
	case "pid":
		return fmt.Sprintf("%v", uos.options.PIDFilter)
	case "executable":
		return fmt.Sprintf("%v", uos.options.Executables)
	case "pattern":
		return fmt.Sprintf("%v", uos.options.FuncPattern)
	case "kernel-pattern":
		return fmt.Sprintf("%v", uos.options.KernelFuncPattern)
	case "tracepoint":
		return fmt.Sprintf("%v", uos.options.Tracepoints)
	case "perf":
		return fmt.Sprintf("%v", uos.options.PerfEvents)
	}
	return ""
}

func (uos *UTraceOptionsSanitizer) Set(val string) error {
	switch uos.field {
	case "pid":
		pid, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("%v is not a valid pid value: %v", val, err)
		}
		uos.options.PIDFilter = append(uos.options.PIDFilter, pid)
	case "executable":
		if len(val) == 0 {
			return nil
		}
		if len(val) > utrace.PathMax {
			return fmt.Errorf("%v is longer than the maximum length allowed for a binary path: got %d, limit is %d", val, len(val), utrace.PathMax)
		}
		// check if the file exists
		if _, err := os.Stat(val); err != nil {
			return fmt.Errorf("can't trace %s: %v", val, err)
		}
		uos.options.Executables = append(uos.options.Executables, val)
	case "pattern":
		if len(val) == 0 {
			return fmt.Errorf("empty pattern")
		}
		fields := strings.SplitN(val, ":", 2)		
		patternStr := fields[len(fields)-1]
		pattern, err := regexp.Compile(patternStr)
		if err != nil {
			return fmt.Errorf("'%s' isn't a valid pattern: %v", patternStr, err)
		}
		binaryPath := ""
		if len(fields) == 2 {
			binaryPath = fields[0]
		}
		uos.options.FuncPattern = &utrace.FuncPattern{Pattern: pattern, Binary: binaryPath} 
	case "kernel-pattern":
		if len(val) == 0 {
			return fmt.Errorf("empty kernel pattern")
		}
		pattern, err := regexp.Compile(val)
		if err != nil {
			return fmt.Errorf("'%s' isn't a valid kernel pattern: %v", val, err)
		}
		uos.options.KernelFuncPattern = pattern
	case "tracepoint":
		if len(val) == 0 {
			return fmt.Errorf("empty tracepoint")
		}
		uos.options.Tracepoints = append(uos.options.Tracepoints, val)
	case "perf":
		if len(val) == 0 {
			return fmt.Errorf("empty perf event")
		}
		uos.options.PerfEvents = append(uos.options.PerfEvents, val)
	}
	return nil
}

func (uos *UTraceOptionsSanitizer) Type() string {
	switch uos.field {
	case "pid":
		return "int array"
	case "executable":
		return "string array"
	case "pattern", "kernel-pattern":
		return "regexp"
	case "tracepoint":
		return "string array"
	case "perf":
		return "string array"
	}
	return ""
}
