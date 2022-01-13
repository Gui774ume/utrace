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

package utrace

import (
	"debug/elf"
	"regexp"
	"sort"
	"time"

	"github.com/pkg/errors"
)

const (
	// MaxUserSymbolsCount is the max number of symbols probed at the same time
	MaxUserSymbolsCount = uint32(100)
	// MaxKernelSymbolsCount is the max number of kernel symbols probed at the same time
	MaxKernelSymbolsCount = uint32(500)
)

var (
	// NotEnoughDataErr indicates that the data retrieved from the perf map is not long enough
	NotEnoughDataErr = errors.New("not enough data")
	// EmptyPatternsErr indicates that both the kernel function and userspace symbol patterns are empty
	EmptyPatternsErr = errors.New("empty patterns")
	// EmptyBinaryPathErr indicates that a userspace symbol pattern was provided but without a binary path
	EmptyBinaryPathErr = errors.New("empty binary path")
	// NoPatternProvidedErr indicates that no function pattern was provided
	NoPatternProvidedErr = errors.New("no function pattern or hook point was provided")
)

// StackID is a unique identifier used to select a stack trace
type StackID uint32

// CombinedID is a unique identifier used to select a combined stack trace (user and kernel)
type CombinedID uint64

// FuncID is the id of a function traced in kernel space
type FuncID int32

// SymbolAddr is the address of a symbol
type SymbolAddr uint64

// BinaryCookie is a unique identifier used to select a TracedBinary
type BinaryCookie uint32

// PathMax - Maximum path length of the binary path handled by utrace
const PathMax = 350

// Options contains the parameters of UTrace
type Options struct {
	FuncPattern       *regexp.Regexp
	KernelFuncPattern *regexp.Regexp
	Tracepoints       []string
	Latency           bool
	StackTraces       bool
	Binary            []string
	PIDFilter         []int
}

func (o Options) check() error {
	if o.FuncPattern == nil && o.KernelFuncPattern == nil {
		return EmptyPatternsErr
	}
	if o.FuncPattern != nil && len(o.Binary) == 0 {
		return EmptyBinaryPathErr
	}
	return nil
}

var (
	// SymbolNotFound is used to notify that a symbol could not be resolved
	SymbolNotFound = elf.Symbol{Name: "[symbol_not_found]"}
)

// Report contains the statistics generated by UTRace
type Report struct {
	stackTracerCount StackTraceCount

	orderedByLatency map[BinaryCookie][]Func
	orderedByHits    map[BinaryCookie][]Func
	functions        map[FuncID]Func
	duration         time.Duration
}

// NewReport instanciates a new Report
func NewReport(duration time.Duration) Report {
	return Report{
		orderedByLatency: make(map[BinaryCookie][]Func),
		orderedByHits:    make(map[BinaryCookie][]Func),
		functions:        make(map[FuncID]Func),
		duration:         duration,
	}
}

// GetStackTraceCount returns the total number of stack traces collected from the kernel
func (r *Report) GetStackTraceCount() StackTraceCount {
	return r.stackTracerCount
}

// GetDuration returns the duration of the trace
func (r *Report) GetDuration() time.Duration {
	return r.duration
}

// GetFunc returns a Func by its FuncID
func (r *Report) GetFunc(id FuncID) Func {
	if id == -1 {
		return NewFunc(SymbolNotFound, nil)
	}
	ret, ok := r.functions[id]
	if !ok {
		return NewFunc(SymbolNotFound, nil)
	}
	return ret
}

// GetFunctionsByHits returns the list of traced functions ordered by their hits count
func (r *Report) GetFunctionsByHits() map[BinaryCookie][]Func {
	if len(r.orderedByHits) == 0 {
		for _, f := range r.functions {
			if f.Binary != nil {
				r.orderedByHits[f.Binary.Cookie] = append(r.orderedByHits[f.Binary.Cookie], f)
			} else {
				r.orderedByHits[0] = append(r.orderedByHits[0], f)

				// check if there is a user space part to the stack traces, if so, create a new Func entry in the
				// relevant binary pool
				cache := make(map[BinaryCookie]*Func)

				for combinedID, stack := range f.stackTraces {
					if stack.Binary == nil {
						continue
					}

					binaryFunc, ok := cache[stack.Binary.Cookie]
					if !ok {
						newFunc := NewFunc(f.Symbol, f.Binary)
						// copy average lagency ... it might not be the actual value for this binary, but that's all
						// we have.
						newFunc.AverageLatency = f.AverageLatency
						cache[stack.Binary.Cookie] = &newFunc
						binaryFunc = &newFunc
					}

					// add stack trace
					binaryFunc.stackTraces[combinedID] = stack
					binaryFunc.Count += uint64(stack.Count)
				}

				for cookie, newFunc := range cache {
					r.orderedByHits[cookie] = append(r.orderedByHits[cookie], *newFunc)
				}
			}
		}
		for key := range r.orderedByHits {
			sort.Sort(orderByHits(r.orderedByHits[key]))
		}
	}
	return r.orderedByHits
}

// GetFunctionsByLatency returns the list of traced functions ordered by their latency
func (r *Report) GetFunctionsByLatency() map[BinaryCookie][]Func {
	if len(r.orderedByLatency) == 0 {
		for _, f := range r.functions {
			if f.Binary != nil {
				r.orderedByLatency[f.Binary.Cookie] = append(r.orderedByLatency[f.Binary.Cookie], f)
			} else {
				r.orderedByLatency[0] = append(r.orderedByLatency[0], f)

				// check if there is a user space part to the stack traces, if so, create a new Func entry in the
				// relevant binary pool
				cache := make(map[BinaryCookie]*Func)

				for combinedID, stack := range f.stackTraces {
					if stack.Binary == nil {
						continue
					}

					binaryFunc, ok := cache[stack.Binary.Cookie]
					if !ok {
						newFunc := NewFunc(f.Symbol, f.Binary)
						// copy average lagency ... it might not be the actual value for this binary, but that's all
						// we have.
						newFunc.AverageLatency = f.AverageLatency
						cache[stack.Binary.Cookie] = &newFunc
						binaryFunc = &newFunc
					}

					// add stack trace
					binaryFunc.stackTraces[combinedID] = stack
					binaryFunc.Count += uint64(stack.Count)
				}

				for cookie, newFunc := range cache {
					r.orderedByLatency[cookie] = append(r.orderedByLatency[cookie], *newFunc)
				}
			}
		}
		for key := range r.orderedByLatency {
			sort.Sort(orderByLatency(r.orderedByLatency[key]))
		}
	}
	return r.orderedByLatency
}

// StackTraceCount holds the amount of traces that were collected or lost
type StackTraceCount struct {
	Kernel     uint64
	LostKernel uint64
	User       uint64
	LostUser   uint64
}

// FuncType is the type of a traced function
type FuncType string

const (
	// Kernel is used for kernel symbols
	Kernel FuncType = "kernel"
	// User is used for user space symbols
	User FuncType = "user"
)

// Func contains the data collected by utrace for a function
type Func struct {
	Type           FuncType
	Symbol         elf.Symbol
	Count          uint64
	AverageLatency time.Duration
	Binary         *TracedBinary

	stackTraces   map[CombinedID]*StackTrace
	orderedByHits []*StackTrace
}

// NewFunc instanciates a new Func
func NewFunc(symbol elf.Symbol, binary *TracedBinary) Func {
	f := Func{
		Symbol:      symbol,
		Binary:      binary,
		stackTraces: make(map[CombinedID]*StackTrace),
	}
	if symbol.Value > 0xffffffff00000000 {
		f.Type = Kernel
	} else {
		f.Type = User
	}
	return f
}

// GetStackTrace returns a stack trace from its StackID
func (f *Func) GetStackTrace(stackID CombinedID) *StackTrace {
	return f.stackTraces[stackID]
}

// GetStackTracesByHits returns the list of stack traces by hits count
func (f *Func) GetStackTracesByHits() []*StackTrace {
	if len(f.orderedByHits) == 0 {
		for _, trace := range f.stackTraces {
			f.orderedByHits = append(f.orderedByHits, trace)
		}
		sort.Sort(orderTraceByHits(f.orderedByHits))
	}
	return f.orderedByHits
}

type orderByHits []Func

func (obh orderByHits) Len() int           { return len(obh) }
func (obh orderByHits) Swap(i, j int)      { obh[i], obh[j] = obh[j], obh[i] }
func (obh orderByHits) Less(i, j int) bool { return obh[i].Count > obh[j].Count }

type orderByLatency []Func

func (obl orderByLatency) Len() int           { return len(obl) }
func (obl orderByLatency) Swap(i, j int)      { obl[i], obl[j] = obl[j], obl[i] }
func (obl orderByLatency) Less(i, j int) bool { return obl[i].AverageLatency > obl[j].AverageLatency }

// StackTrace contains the ordered list of symbols of a stack trace
type StackTrace struct {
	Count            int
	Binary           *TracedBinary
	UserStacktrace   []StackTraceNode
	KernelStackTrace []StackTraceNode
}

type orderTraceByHits []*StackTrace

func (otbh orderTraceByHits) Len() int           { return len(otbh) }
func (otbh orderTraceByHits) Swap(i, j int)      { otbh[i], otbh[j] = otbh[j], otbh[i] }
func (otbh orderTraceByHits) Less(i, j int) bool { return otbh[i].Count > otbh[j].Count }

// NewStackTrace returns a new StackTrace initialized with the provided count
func NewStackTrace(count int, binary *TracedBinary) *StackTrace {
	return &StackTrace{
		Count:  count,
		Binary: binary,
	}
}

// StackTraceNode represents a node of a stack trace
type StackTraceNode struct {
	Type   FuncType
	FuncID FuncID
	Offset SymbolAddr
	Symbol elf.Symbol
}

type kernelCounter struct {
	CumulatedTime uint64
	Count         uint64
}

// TraceEvent is a kernel trace event retrieved from a perf map
type TraceEvent struct {
	Pid           uint32
	Tid           uint32
	UserStackID   StackID
	KernelStackID StackID
	FuncID        FuncID
	Cookie        BinaryCookie
}

// UnmarshalBinary unmarshals the binary representation of a trace event
func (te *TraceEvent) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 24 {
		return 0, NotEnoughDataErr
	}

	te.Pid = ByteOrder.Uint32(data[0:4])
	te.Tid = ByteOrder.Uint32(data[4:8])
	te.UserStackID = StackID(ByteOrder.Uint32(data[8:12]))
	te.KernelStackID = StackID(ByteOrder.Uint32(data[12:16]))
	te.FuncID = FuncID(ByteOrder.Uint32(data[16:20]))
	te.Cookie = BinaryCookie(ByteOrder.Uint32(data[20:24]))
	return 24, nil
}

type TracedBinary struct {
	Path         string
	ResolvedPath string
	Inode        uint64
	Size         int64
	Cookie       BinaryCookie
	Pids         []int

	symbolsCache       map[SymbolAddr]elf.Symbol
	symbolNameToFuncID map[string]FuncID
	file               *elf.File
}

type TracedSymbol struct {
	symbol elf.Symbol
	binary *TracedBinary
}
