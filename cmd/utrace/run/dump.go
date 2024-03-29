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
	"io/ioutil"
	"os"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"

	"github.com/Gui774ume/utrace/pkg/utrace"
)

func dump(report utrace.Report, options CLIOptions, tracer *utrace.UTrace) {
	if options.UTraceOptions.Latency {
		dumpReportWithLatency(report, tracer)
	} else {
		dumpReport(report, tracer)
	}
	var printLater []string
	for cookie, funcs := range report.GetFunctionsByHits() {
		binary := tracer.TracedBinaries[cookie]

		if options.UTraceOptions.StackTraces {
			if binary == nil {
				fmt.Printf("\n* Dumping kernel stack traces:\n")
			} else {
				fmt.Printf("\n* Dumping stack traces for %s:\n", binaryTitle(binary))
			}
			outputFile, err := dumpStackTraces(report, funcs)
			if err != nil {
				logrus.Warnf("couldn't generate stack trace dump for %s: %s", binaryTitle(binary), err)
			} else {
				if binary != nil {
					printLater = append(printLater, fmt.Sprintf("User space stack traces dump for %s: %s", binaryTitle(binary), outputFile))
				} else {
					printLater = append(printLater, fmt.Sprintf("Kernel stack traces dump: %s", outputFile))
				}
			}
		}

		if options.GenerateGraph {
			outputFile, err := generateDotGraph(report, funcs, tracer.TracedBinaries[cookie])
			if err != nil {
				logrus.Warnf("couldn't generate graph: %s", err)
			} else {
				if binary == nil {
					printLater = append(printLater, fmt.Sprintf("Kernel space graph: %s", outputFile))
				} else {
					printLater = append(printLater, fmt.Sprintf("Userspace graph for %s: %s", binaryTitle(binary), outputFile))
				}
			}
		}
	}
	logrus.Infof("%d user space stack traces collected (%d lost)", report.GetStackTraceCount().User, report.GetStackTraceCount().LostUser)
	logrus.Infof("%d kernel space stack traces collected (%d lost)", report.GetStackTraceCount().Kernel, report.GetStackTraceCount().LostKernel)
	logrus.Infof("Tracing lasted for %s", report.GetDuration())

	for _, msg := range printLater {
		logrus.Infoln(msg)
	}
}

func generateNodeID(node utrace.StackTraceNode) string {
	name := node.Symbol.Name
	if name == utrace.SymbolNotFound.Name {
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

func generateDotGraph(report utrace.Report, tracedFuncs []utrace.Func, binary *utrace.TracedBinary) (string, error) {
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
	for i, f := range tracedFuncs {
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
			if f.Symbol.Name == utrace.SymbolNotFound.Name {
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
					if n.Symbol.Name == utrace.SymbolNotFound.Name {
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
					if n.Symbol.Name == utrace.SymbolNotFound.Name {
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
	if binary != nil {
		data.Title += fmt.Sprintf("[binary: %s]", binaryTitle(binary))
	}
	data.Title += fmt.Sprintf("\n[kernel: %d traced function(s), %d stack trace(s), %d lost]", krnFuncCount, report.GetStackTraceCount().Kernel, report.GetStackTraceCount().LostKernel)
	data.Title += fmt.Sprintf("\n[user: %d traced function(s), %d stack trace(s), %d lost]", usrFuncCount, report.GetStackTraceCount().User, report.GetStackTraceCount().LostUser)
	data.Title += fmt.Sprintf("\n[duration: %s]", report.GetDuration())

	f, err := ioutil.TempFile("/tmp", "utrace-graph-")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := os.Chmod(f.Name(), os.ModePerm); err != nil {
		return "", err
	}

	t := template.Must(template.New("tmpl").Parse(tmpl))
	if err := t.Execute(f, data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func dumpReport(report utrace.Report, tracer *utrace.UTrace) {
	for cookie, funcs := range report.GetFunctionsByHits() {
		binary := tracer.TracedBinaries[cookie]
		if binary != nil {
			fmt.Printf("\nUserspace and kernel space functions hits for %s:\n", binaryTitle(binary))
		} else {
			fmt.Printf("\nKernel functions hits:\n")
		}
		fmt.Printf("\n%10v %s\n", "COUNT", "FUNC_NAME")
		for _, f := range funcs {
			fmt.Printf("%10v %s\n", f.Count, f.Symbol.Name)
		}
	}
}

func dumpReportWithLatency(report utrace.Report, tracer *utrace.UTrace) {
	for cookie, funcs := range report.GetFunctionsByLatency() {
		binary := tracer.TracedBinaries[cookie]
		if binary != nil {
			fmt.Printf("\nUserspace and kernel space functions ordered by latency for %s:\n", binaryTitle(binary))
		} else {
			fmt.Printf("\nKernel functions ordered by latency:\n")
		}
		fmt.Printf("%10v %20v %s\n", "COUNT", "AVG_LATENCY", "FUNC_NAME")
		for _, f := range funcs {
			fmt.Printf("%10v %20v %s\n", f.Count, f.AverageLatency, f.Symbol.Name)
		}
	}
}

const (
	stackTracesDumpHeader     = "total_hits;symbol_name;symbol_type;symbol_addr;offset;avg_latency;\n"
	stackTracesDumpNodeFormat = "%s;%s;0x%x;%d;%s;"
)

func binaryTitle(binary *utrace.TracedBinary) string {
	var str string
	if len(binary.ResolvedPath) > 0 {
		str += binary.ResolvedPath
	} else {
		str += binary.Path
	}
	if len(binary.Pids) > 0 {
		str += fmt.Sprintf(" %v", binary.Pids)
	}
	return str
}

func dumpStackTraces(report utrace.Report, tracedFuncs []utrace.Func) (string, error) {
	d, err := ioutil.TempFile("/tmp", "utrace-dump-")
	if err != nil {
		return "", err
	}
	defer d.Close()
	if _, err = d.WriteString(stackTracesDumpHeader); err != nil {
		return "", err
	}

	var latency time.Duration
	for _, f := range tracedFuncs {
		fmt.Printf("\n  - symbol %v:\n", f.Symbol.Name)
		if len(f.GetStackTracesByHits()) == 0 {
			continue
		}

		for stackID, trace := range f.GetStackTracesByHits() {
			fmt.Printf("\n\t* Stack %d [%d hit(s)]\n", stackID, trace.Count)
			if _, err = d.WriteString(fmt.Sprintf("%d;", trace.Count)); err != nil {
				return "", err
			}

			for _, n := range trace.UserStacktrace {
				latency = 0
				fmt.Printf("\t\t- %s (offset: 0x%x)\n", n.Symbol.Name, n.Offset)
				if fun := report.GetFunc(n.FuncID); fun.Symbol.Name != utrace.SymbolNotFound.Name {
					fmt.Printf("\t\t\thit(s): %d avg_latency: %s\n", fun.Count, fun.AverageLatency)
					latency = fun.AverageLatency
				}
				if _, err = d.WriteString(fmt.Sprintf(stackTracesDumpNodeFormat, n.Symbol.Name, n.Type, n.Symbol.Value, n.Offset, latency)); err != nil {
					return "", err
				}
			}
			if len(trace.KernelStackTrace) > 0 {
				fmt.Print("\t\t--------------------------\n")
			}
			for _, n := range trace.KernelStackTrace {
				latency = 0
				fmt.Printf("\t\t- %s (offset: 0x%x)\n", n.Symbol.Name, n.Offset)
				if fun := report.GetFunc(n.FuncID); fun.Symbol.Name != utrace.SymbolNotFound.Name {
					fmt.Printf("\t\t\thit(s): %d avg_latency: %s\n", fun.Count, fun.AverageLatency)
					latency = fun.AverageLatency
				}
				if _, err = d.WriteString(fmt.Sprintf(stackTracesDumpNodeFormat, n.Symbol.Name, n.Type, n.Symbol.Value, n.Offset, latency)); err != nil {
					return "", err
				}
			}
			if _, err = d.WriteString("\n"); err != nil {
				return "", err
			}
		}
	}
	return d.Name(), nil
}
