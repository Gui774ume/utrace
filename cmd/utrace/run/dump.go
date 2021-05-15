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
	"io/ioutil"
	"os"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"

	"github.com/Gui774ume/utrace/pkg/utrace"
)

func dump(report utrace.Report, options CLIOptions) {
	if options.UTraceOptions.Latency {
		dumpReportWithLatency(report)
	} else {
		dumpReport(report)
	}
	if options.UTraceOptions.StackTraces {
		if err := dumpStackTraces(report); err != nil {
			logrus.Warnf("couldn't generate stack trace dump: %s", err)
		}
	}
	logrus.Infof("%d user space stack traces collected (%d lost)", report.GetStackTraceCount().User, report.GetStackTraceCount().LostUser)
	logrus.Infof("%d kernel space stack traces collected (%d lost)", report.GetStackTraceCount().Kernel, report.GetStackTraceCount().LostKernel)
	logrus.Infof("Tracing lasted for %s", report.GetDuration())

	if options.GenerateGraph {
		if err := generateDotGraph(report, options); err != nil {
			logrus.Warnf("couldn't generate graph: %s", err)
		}
	}

}

func generateNodeID(node utrace.StackTraceNode) string {
	name := node.Symbol.Name
	if name == utrace.UserSymbolNotFound.Name || name == utrace.KernelSymbolNotFound.Name {
		if node.Symbol.Value > 0 {
			name = fmt.Sprintf("0x%x", node.Symbol.Value)
		} else {
			name = fmt.Sprintf("0x%x", node.Offset)
		}
	}
	var id string
	for _, b := range blake2b.Sum256([]byte(name)) {
		id += fmt.Sprintf("%v", b)
	}
	return id
}

type node struct {
	ID    string
	Label string
	Size  int
	Color string
	Hits  uint64
}

type graph struct {
	Title             string
	Nodes             map[string]*node
	UserStackTraces   []string
	KernelStackTraces []string
	Bridges           []string
}

var (
	userColor   = "#8fbbff"
	kernelColor = "#77bf77"
	bridgeColor = "orange"
)

func reverse(lines []string) []string {
	for i := 0; i < len(lines)/2; i++ {
		j := len(lines) - i - 1
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines
}

func generateDotGraph(report utrace.Report, options CLIOptions) error {
	tmpl := `strict digraph {
      label     = "{{ .Title }}"
      labelloc  =  "t"
      fontsize  = 75
      fontcolor = "black"
      fontname = "arial"

	  node [style=rounded, style="rounded", shape=record, fontname = "arial"]
      edge [color="#aaaaaa"]
	  {{ range .Nodes }}
	  {{ .ID }} [label="{{ .Label }}", fontsize={{ .Size }}, color="{{ .Color }}"]{{ end }}
	
	  {{ range .UserStackTraces }}
      {{ . }}
      {{ end }}
      {{ range .Bridges }}
      {{ . }} [dir="both"]
      {{ end }}
      {{ range .KernelStackTraces }}
      {{ . }}
      {{ end }}
	}
`
	data := graph{
		Nodes: make(map[string]*node),
	}

	maxHits := uint64(1)
	var usrFuncCount, krnFuncCount int
	for i, f := range report.GetFunctionsByHits() {
		if f.Type == utrace.Kernel {
			krnFuncCount++
		} else {
			usrFuncCount++
		}

		if f.Count == 0 {
			continue
		}

		if i == 0 {
			maxHits = f.Count
		}

		fNodeID := generateNodeID(utrace.StackTraceNode{Symbol: f.Symbol})
		if graphNode, ok := data.Nodes[fNodeID]; ok {
			graphNode.Label = fmt.Sprintf("{ %s | hits:%d | avg_latency:%s }", f.Symbol.Name, f.Count, f.AverageLatency)
			graphNode.Hits += f.Count
		} else {
			var color string
			if f.Type == utrace.Kernel {
				color = kernelColor
			} else {
				color = userColor
			}
			data.Nodes[fNodeID] = &node{
				ID:    fNodeID,
				Size:  1,
				Hits:  f.Count,
				Color: color,
				Label: fmt.Sprintf("{ %s | hits:%d | avg_latency:%s }", f.Symbol.Name, f.Count, f.AverageLatency),
			}
			if f.Symbol.Name == utrace.KernelSymbolNotFound.Name || f.Symbol.Name == utrace.UserSymbolNotFound.Name {
				data.Nodes[fNodeID].Label = fmt.Sprintf("{ 0x%x }", f.Symbol.Value)
			}
		}

		maxTraceHits := 1
		for j, trace := range f.GetStackTracesByHits() {
			if j == 0 {
				maxTraceHits = trace.Count
			}
			var usertraceStr, kernelTraceStr string
			var userBridge, kernelBridge string
			for i, n := range trace.UserStacktrace {
				nodeID := generateNodeID(n)
				if i == 0 {
					userBridge = nodeID
				}
				if graphNode, ok := data.Nodes[nodeID]; ok {
					graphNode.Size += trace.Count
				} else {
					data.Nodes[nodeID] = &node{
						ID:    nodeID,
						Size:  trace.Count,
						Color: userColor,
						Label: fmt.Sprintf("{ %s }", n.Symbol.Name),
					}
					if n.Symbol.Name == utrace.UserSymbolNotFound.Name {
						data.Nodes[nodeID].Label = fmt.Sprintf("{ 0x%x }", n.Offset)
					}
				}
				if len(usertraceStr) == 0 {
					usertraceStr = nodeID
				} else {
					usertraceStr = nodeID + " -> " + usertraceStr
				}
			}
			usertraceStr += fmt.Sprintf(`[color="%d", colorscheme="blues9"]`, int(6*float64(trace.Count)/float64(maxTraceHits)+3))
			data.UserStackTraces = append(data.UserStackTraces, usertraceStr)

			for _, n := range trace.KernelStackTrace {
				nodeID := generateNodeID(n)
				if graphNode, ok := data.Nodes[nodeID]; ok {
					graphNode.Size += trace.Count
				} else {
					data.Nodes[nodeID] = &node{
						ID:    nodeID,
						Size:  trace.Count,
						Color: kernelColor,
						Label: fmt.Sprintf("{ %s }", n.Symbol.Name),
					}
					if n.Symbol.Name == utrace.KernelSymbolNotFound.Name {
						data.Nodes[nodeID].Label = fmt.Sprintf("{ 0x%x }", n.Offset)
					}
				}
				if len(kernelTraceStr) == 0 {
					kernelTraceStr = nodeID
				} else {
					kernelTraceStr = nodeID + " -> " + kernelTraceStr
				}
				kernelBridge = nodeID
			}
			kernelTraceStr += fmt.Sprintf(`[color="%d", colorscheme="greens9"]`, int(6*float64(trace.Count)/float64(maxTraceHits)+3))
			data.KernelStackTraces = append(data.KernelStackTraces, kernelTraceStr)

			if len(kernelBridge) > 0 && len(userBridge) > 0 {
				data.Bridges = append(data.Bridges,
					fmt.Sprintf(`%s -> %s [color="%s"]`, userBridge, kernelBridge, bridgeColor))
			}
		}
		data.UserStackTraces = reverse(data.UserStackTraces)
		data.KernelStackTraces = reverse(data.KernelStackTraces)
	}

	// normalize nodes size
	var maxCount int
	for _, graphNode := range data.Nodes {
		if maxCount < graphNode.Size {
			maxCount = graphNode.Size
		}
	}
	for _, graphNode := range data.Nodes {
		graphNode.Size = 10 + (30 * graphNode.Size / maxCount) + int(10*graphNode.Hits/maxHits)
	}

	// generate graph title
	if len(options.UTraceOptions.Binary) > 0 {
		data.Title += fmt.Sprintf("[binary: %s]", options.UTraceOptions.Binary)
	}
	data.Title += fmt.Sprintf("\n[kernel: %d traced function(s), %d stack trace(s), %d lost]", krnFuncCount, report.GetStackTraceCount().Kernel, report.GetStackTraceCount().LostKernel)
	data.Title += fmt.Sprintf("\n[user: %d traced function(s), %d stack trace(s), %d lost]", usrFuncCount, report.GetStackTraceCount().User, report.GetStackTraceCount().LostUser)
	data.Title += fmt.Sprintf("\n[duration: %s]", report.GetDuration())

	f, err := ioutil.TempFile("/tmp", "utrace-graph-")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.Chmod(f.Name(), os.ModePerm); err != nil {
		return err
	}

	t := template.Must(template.New("tmpl").Parse(tmpl))
	if err := t.Execute(f, data); err != nil {
		return err
	}
	logrus.Infof("Graph generated: %s", f.Name())
	return nil
}

func dumpReport(report utrace.Report) {
	fmt.Printf("%10v %s\n", "COUNT", "FUNC_NAME")
	for _, f := range report.GetFunctionsByHits() {
		fmt.Printf("%10v %s\n", f.Count, f.Symbol.Name)
	}
}

func dumpReportWithLatency(report utrace.Report) {
	fmt.Printf("%10v %20v %s\n", "COUNT", "AVG_LATENCY", "FUNC_NAME")
	for _, f := range report.GetFunctionsByLatency() {
		fmt.Printf("%10v %20v %s\n", f.Count, f.AverageLatency, f.Symbol.Name)
	}
}

const (
	stackTracesDumpHeader = "total_hits;symbol_name;symbol_type;offset;avg_latency;\n"
	stackTracesDumpNodeFormat = "%s;%s;%d;%s;"
)

func dumpStackTraces(report utrace.Report) error {
	d, err := ioutil.TempFile("/tmp", "utrace-dump-")
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err = d.WriteString(stackTracesDumpHeader); err != nil {
		return err
	}

	var latency time.Duration
	for _, f := range report.GetFunctionsByHits() {
		if len(f.GetStackTracesByHits()) == 0 {
			continue
		}
		fmt.Printf("\nDumping stack traces for symbol %v:\n", f.Symbol.Name)

		for stackID, trace := range f.GetStackTracesByHits() {
			fmt.Printf("\t* Stack %d [%d hit(s)]\n", stackID, trace.Count)
			if _, err = d.WriteString(fmt.Sprintf("%d;", trace.Count)); err != nil {
				return err
			}

			for _, n := range trace.UserStacktrace {
				latency = 0
				fmt.Printf("\t\t- %s (offset: 0x%x)\n", n.Symbol.Name, n.Offset)
				if fun := report.GetFunc(n.FuncID, utrace.User); fun.Symbol.Name != utrace.UserSymbolNotFound.Name {
					fmt.Printf("\t\t\thit(s): %d avg_latency: %s\n", fun.Count, fun.AverageLatency)
					latency = fun.AverageLatency
				}
				if _, err = d.WriteString(fmt.Sprintf(stackTracesDumpNodeFormat, n.Symbol.Name, n.Type, n.Offset, latency)); err != nil {
					return err
				}
			}
			if len(trace.KernelStackTrace) > 0 {
				fmt.Print("\t\t--------------------------\n")
			}
			for _, n := range trace.KernelStackTrace {
				latency = 0
				fmt.Printf("\t\t- %s (offset: 0x%x)\n", n.Symbol.Name, n.Offset)
				if fun := report.GetFunc(n.FuncID, utrace.Kernel); fun.Symbol.Name != utrace.KernelSymbolNotFound.Name {
					fmt.Printf("\t\t\thit(s): %d avg_latency: %s\n", fun.Count, fun.AverageLatency)
					latency = fun.AverageLatency
				}
				if _, err = d.WriteString(fmt.Sprintf(stackTracesDumpNodeFormat, n.Symbol.Name, n.Type, n.Offset, latency)); err != nil {
					return err
				}
			}
			if _, err = d.WriteString("\n"); err != nil {
				return err
			}
		}
	}
	logrus.Infof("Stack traces dump generated: %s", d.Name())
	return nil
}
