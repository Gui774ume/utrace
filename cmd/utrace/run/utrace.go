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
	"os/signal"

	"github.com/Gui774ume/utrace/pkg/utrace"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func utraceCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	if options.GenerateGraph {
		options.UTraceOptions.StackTraces = true
	}

	tracer := utrace.NewUTrace(options.UTraceOptions)
	if err := tracer.Start(); err != nil {
		return errors.Wrap(err, "couldn't start")
	}

	wait()

	// Dump hit counters
	report, err := tracer.Stop()
	if err != nil {
		logrus.Error(errors.Wrap(err, "couldn't dump utrace"))
		return nil
	}

	dump(report, options, tracer)
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
