/*
Copyright © 2020 GUILLAUME FOURNIER

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
	"github.com/Gui774ume/utrace/pkg/utrace"
	"os"
	"regexp"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

// PathSanitizer is a path sanitizer that ensures that the provided path exists
type PathSanitizer struct {
	path *string
}

// NewPathSanitizer creates a new instance of PathSanitizer. The sanitized path will be written in the provided string
func NewPathSanitizer(sanitizedPath *string) *PathSanitizer {
	return &PathSanitizer{
		path: sanitizedPath,
	}
}

func (ps *PathSanitizer) String() string {
	return fmt.Sprintf("%v", *ps.path)
}

func (ps *PathSanitizer) Set(val string) error {
	if len(val) == 0 {
		return nil
	}
	if _, err := os.Stat(val); err != nil {
		return err
	}
	*ps.path = val
	return nil
}

func (ps *PathSanitizer) Type() string {
	return "string"
}

// RegexpSanitizer is a regexp sanitizer that ensures that the provided regexp is valid
type RegexpSanitizer struct {
	pattern **regexp.Regexp
}

// NewRegexpSanitizerWithDefault creates a new instance of RegexpSanitizer. The sanitized regexp will be written in the provided
// regexp pointer
func NewRegexpSanitizerWithDefault(sanitizedPattern **regexp.Regexp, defaultPattern *regexp.Regexp) *RegexpSanitizer {
	*sanitizedPattern = defaultPattern
	return &RegexpSanitizer{
		pattern: sanitizedPattern,
	}
}

func (rs *RegexpSanitizer) String() string {
	return "*"
}

func (rs *RegexpSanitizer) Set(val string) error {
	if len(val) == 0 {
		return errors.New("empty pattern")
	}
	pattern, err := regexp.Compile(val)
	if err != nil {
		return errors.Wrap(err, "invalid pattern")
	}
	*rs.pattern = pattern
	return nil
}

func (rs *RegexpSanitizer) Type() string {
	return "regexp"
}
