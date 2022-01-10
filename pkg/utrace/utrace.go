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
	"bytes"
	"debug/elf"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/utrace/pkg/assets"
)

// UTrace is the main UTrace structure
type UTrace struct {
	options        Options
	kernelCounters *ebpf.Map
	stackTraces    *ebpf.Map
	binaryPath     *ebpf.Map
	lostCount      *ebpf.Map
	tracedPIDs     *ebpf.Map
	manager        *manager.Manager
	managerOptions manager.Options
	startTime      time.Time
	funcIDCursor   FuncID

	matchingFuncCache       map[FuncID]elf.Symbol
	symbolNameToFuncID      map[string]FuncID
	symbolsCache            map[SymbolAddr]elf.Symbol
	kallsymsCache           map[SymbolAddr]elf.Symbol
	matchingFuncStackTraces map[FuncID]map[CombinedID]*StackTrace

	kernelStackTraceCounter uint64
	kernelStackTraceLost    uint64
	userStackTraceCounter   uint64
	userStackTraceLost      uint64
}

// NewUTrace creates a new UTrace instance
func NewUTrace(options Options) *UTrace {
	return &UTrace{
		options:                 options,
		matchingFuncCache:       make(map[FuncID]elf.Symbol),
		symbolNameToFuncID:      make(map[string]FuncID),
		symbolsCache:            make(map[SymbolAddr]elf.Symbol),
		kallsymsCache:           make(map[SymbolAddr]elf.Symbol),
		matchingFuncStackTraces: make(map[FuncID]map[CombinedID]*StackTrace),
	}
}

// Start hooks on the requested symbols and begins tracing
func (u *UTrace) Start() error {
	// ensure that at least one function pattern was provided
	if u.options.FuncPattern == nil && u.options.KernelFuncPattern == nil {
		return NoPatternProvidedErr
	}

	if err := u.start(); err != nil {
		return err
	}

	logrus.Infof("Tracing started on %d symbols ... (Ctrl + C to stop)", len(u.matchingFuncCache))
	return nil
}

// Dump dumps the the statistiques collected by UTrace
func (u *UTrace) Dump() (Report, error) {
	report := NewReport(time.Now().Sub(u.startTime))
	var id FuncID
	stats := make([]kernelCounter, runtime.NumCPU())
	iterator := u.kernelCounters.Iterate()

	for iterator.Next(&id, &stats) {
		symbol, ok := u.matchingFuncCache[id]
		if !ok {
			continue
		}
		f := NewFunc(symbol)
		if symbol.Value > 0xffffffff00000000 {
			f.Type = Kernel
		} else {
			f.Type = User
		}
		for _, cpuStat := range stats {
			f.Count += cpuStat.Count
			f.AverageLatency += time.Duration(cpuStat.CumulatedTime) * time.Nanosecond
		}
		if f.Count > 0 {
			f.AverageLatency = time.Duration(float64(f.AverageLatency.Nanoseconds()) / float64(f.Count))
		}

		f.stackTraces = u.matchingFuncStackTraces[id]

		report.functions[id] = f
	}
	report.stackTracerCount.Kernel = atomic.LoadUint64(&u.kernelStackTraceCounter)
	report.stackTracerCount.User = atomic.LoadUint64(&u.userStackTraceCounter)
	if err := u.lostCount.Lookup([4]byte{0}, &report.stackTracerCount.LostUser); err != nil {
		logrus.Warnf("failed to retrieve user stack trace lost count: %s", err)
	}
	if err := u.lostCount.Lookup([4]byte{1}, &report.stackTracerCount.LostKernel); err != nil {
		logrus.Warnf("failed to retrieve kernel stack trace lost count: %s", err)
	}
	report.stackTracerCount.LostUser += atomic.LoadUint64(&u.userStackTraceLost)
	report.stackTracerCount.LostKernel += atomic.LoadUint64(&u.kernelStackTraceLost)
	return report, iterator.Err()
}

// Stop shuts down UTrace
func (u *UTrace) Stop() error {
	// Close the manager
	return errors.Wrap(u.manager.Stop(manager.CleanAll), "couldn't stop manager")
}

// nextFuncID returns the next funcID
func (u *UTrace) nextFuncID() FuncID {
	id := u.funcIDCursor
	u.funcIDCursor++
	return id
}

func (u *UTrace) setupDefaultManager() {
	execTracepoint := &manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID:          "utrace",
			EBPFSection:  "tracepoint/sched/sched_process_exec",
			EBPFFuncName: "tracepoint_sched_sched_process_exec",
		},
	}
	u.manager = &manager.Manager{
		Probes: []*manager.Probe{execTracepoint},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{
					Name: "trace_events",
				},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8192 * os.Getpagesize(),
					DataHandler:        u.TraceEventsHandler,
				},
			},
		},
	}
	u.managerOptions.DefaultKProbeMaxActive = 50
	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &manager.OneOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: execTracepoint.ProbeIdentificationPair,
			},
		},
	})
	u.managerOptions.MapSpecEditors = make(map[string]manager.MapSpecEditor)
	if u.options.StackTraces {
		u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "send_stack_trace",
			Value: uint64(1),
		})
	}
	u.managerOptions.RLimit = &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}
}

func (u *UTrace) selectMaps() error {
	var err error
	u.kernelCounters, _, err = u.manager.GetMap("counters")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/counters")
	}

	u.stackTraces, _, err = u.manager.GetMap("stack_traces")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/stack_traces")
	}

	u.binaryPath, _, err = u.manager.GetMap("binary_path")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/binary_path")
	}

	u.lostCount, _, err = u.manager.GetMap("lost_traces")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/lost_traces")
	}

	u.tracedPIDs, _, err = u.manager.GetMap("traced_pids")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/traced_pids")
	}
	return nil
}

func (u *UTrace) start() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup a default manager
	u.setupDefaultManager()

	if u.options.PIDFilter > 0 && len(u.options.Binary) == 0 {
		u.options.Binary = fmt.Sprintf("/proc/%d/exe", u.options.PIDFilter)
	}

	// generate uprobes if a binary file is provided
	if len(u.options.Binary) > 0 {
		if err = u.generateUProbes(); err != nil {
			return errors.Wrap(err, "couldn't generate uprobes")
		}
	}

	// setup kprobes if a kernel function pattern was provided
	if u.options.KernelFuncPattern != nil {
		if err = u.generateKProbes(); err != nil {
			return errors.Wrap(err, "couldn't generate kprobes")
		}
	}

	if len(u.symbolNameToFuncID) == 0 {
		return errors.New("nothing matched the provided pattern(s)")
	}

	u.managerOptions.MapSpecEditors["counters"] = manager.MapSpecEditor{
		Type:       ebpf.PerCPUArray,
		MaxEntries: uint32(len(u.symbolNameToFuncID)),
		EditorFlag: manager.EditMaxEntries,
	}

	// initialize the manager
	if err = u.manager.InitWithOptions(bytes.NewReader(buf), u.managerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// select kernel space maps
	if err = u.selectMaps(); err != nil {
		return err
	}

	// insert binary path in kernel space
	pathB := [PathMax]byte{}
	copy(pathB[:], u.options.Binary)
	if err = u.binaryPath.Put(pathB, uint32(1)); err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "failed to insert binary path in kernel")
	}

	// insert pid
	if u.options.PIDFilter > 0 {
		if err = u.tracedPIDs.Put(uint32(u.options.PIDFilter), uint32(1)); err != nil {
			_ = u.manager.Stop(manager.CleanAll)
			return errors.Wrap(err, "failed to insert PID filter")
		}
	}

	// start the manager
	if err = u.manager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start manager")
	}

	u.startTime = time.Now()
	return nil
}

func (u *UTrace) generateUProbes() error {
	// fetch the list of symbols in the provided binary
	f, syms, err := manager.OpenAndListSymbols(u.options.Binary)
	if err != nil {
		return err
	}

	// from the entire list of symbols, only keep the functions that match the provided pattern
	var matches []elf.Symbol
	for _, sym := range syms {
		u.symbolsCache[SymbolAddr(sym.Value)] = sym

		if u.options.FuncPattern != nil {
			if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && u.options.FuncPattern.MatchString(sym.Name) {
				matches = append(matches, sym)
			}
		}
	}

	if u.options.FuncPattern == nil {
		return nil
	}

	// relocate the function address with the base address of the binary
	manager.SanitizeUprobeAddresses(f, matches)

	if uint32(len(matches)) > MaxUserSymbolsCount {
		logrus.Warnf("%d symbols matched the provided pattern, only the first %d symbols will be traced.", len(matches), MaxUserSymbolsCount)
		matches = matches[0:MaxUserSymbolsCount]
	}

	// configure a probe for each symbol we're going to hook onto
	var oneOfSelector manager.OneOf
	var constantEditors []manager.ConstantEditor
	for _, sym := range matches {
		escapedName := sanitizeFuncName(sym.Name)
		funcID := u.nextFuncID()
		probe := &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          escapedName,
				EBPFSection:  "uprobe/utrace",
				EBPFFuncName: "uprobe_utrace",
			},
			CopyProgram:   true,
			BinaryPath:    u.options.Binary,
			UprobeOffset:  sym.Value,
			MatchFuncName: fmt.Sprintf(`^%s$`, escapedName),
		}
		u.manager.Probes = append(u.manager.Probes, probe)
		oneOfSelector.Selectors = append(oneOfSelector.Selectors, &manager.ProbeSelector{
			ProbeIdentificationPair: probe.ProbeIdentificationPair,
		})
		constantEditors = append(constantEditors, manager.ConstantEditor{
			Name:  "func_id",
			Value: uint64(funcID),
			ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
				probe.ProbeIdentificationPair,
			},
		})

		if u.options.Latency {
			retProbe := &manager.Probe{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          escapedName,
					EBPFSection:  "uretprobe/utrace",
					EBPFFuncName: "uretprobe_utrace",
				},
				CopyProgram:   true,
				BinaryPath:    u.options.Binary,
				UprobeOffset:  sym.Value,
				MatchFuncName: fmt.Sprintf(`^%s$`, escapedName),
			}
			u.manager.Probes = append(u.manager.Probes, retProbe)
			oneOfSelector.Selectors = append(oneOfSelector.Selectors, &manager.ProbeSelector{
				ProbeIdentificationPair: retProbe.ProbeIdentificationPair,
			})
			constantEditors = append(constantEditors, manager.ConstantEditor{
				Name:  "func_id",
				Value: uint64(funcID),
				ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
					retProbe.ProbeIdentificationPair,
				},
			})
		}

		u.matchingFuncCache[funcID] = sym
		u.symbolNameToFuncID[sym.Name] = funcID
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

func (u *UTrace) parseKallsyms() error {
	kallsymsRaw, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		return err
	}

	var kallsyms []*elf.Symbol
	for _, sym := range strings.Split(string(kallsymsRaw), "\n") {
		splittedSym := strings.Split(sym, " ")
		if len(splittedSym) != 3 {
			continue
		}
		if splittedSym[1] != "T" && splittedSym[1] != "t" {
			continue
		}
		addr, err := strconv.ParseUint(splittedSym[0], 16, 64)
		if err != nil {
			continue
		}
		splittedName := strings.Split(splittedSym[2], "\t")
		kallsyms = append(kallsyms, &elf.Symbol{
			Name:  splittedName[0],
			Value: addr,
			Info:  uint8(elf.STT_FUNC),
		})
	}

	// compute symbol sizes
	kallsymsLen := len(kallsyms)
	for i, sym := range kallsyms {
		var size uint64
		if i < kallsymsLen-1 {
			size = kallsyms[i+1].Value - sym.Value
		}
		sym.Size = size
		u.kallsymsCache[SymbolAddr(sym.Value)] = *sym
	}

	return nil
}

func (u *UTrace) generateKProbes() error {
	if err := u.parseKallsyms(); err != nil {
		return errors.Wrap(err, "couldn't parse /proc/kallsyms")
	}

	// from the list of kernel symbols, only keep the functions that match the provided pattern
	var matches []elf.Symbol
	for _, sym := range u.kallsymsCache {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && u.options.KernelFuncPattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if uint32(len(matches)) > MaxKernelSymbolsCount {
		logrus.Warnf("%d kernel symbols matched the provided pattern, only the first %d symbols will be traced.", len(matches), MaxKernelSymbolsCount)
		matches = matches[0:MaxKernelSymbolsCount]
	}

	// configure a probe for each symbol we're going to hook onto
	var oneOfSelector manager.OneOf
	var constantEditors []manager.ConstantEditor
	for _, sym := range matches {
		escapedName := sanitizeFuncName(sym.Name)
		funcID := u.nextFuncID()
		probe := &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          escapedName,
				EBPFSection:  "kprobe/utrace",
				EBPFFuncName: "kprobe_utrace",
			},
			CopyProgram:   true,
			MatchFuncName: fmt.Sprintf(`^%s$`, escapedName),
		}
		u.manager.Probes = append(u.manager.Probes, probe)
		oneOfSelector.Selectors = append(oneOfSelector.Selectors, &manager.ProbeSelector{
			ProbeIdentificationPair: probe.ProbeIdentificationPair,
		})
		constantEditors = append(constantEditors, manager.ConstantEditor{
			Name:  "func_id",
			Value: uint64(funcID),
			ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
				probe.ProbeIdentificationPair,
			},
		})
		if len(u.options.Binary) > 0 || u.options.PIDFilter > 0 {
			constantEditors = append(constantEditors, manager.ConstantEditor{
				Name:  "filter_user_binary",
				Value: uint64(1),
				ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
					probe.ProbeIdentificationPair,
				},
			})
		}

		if u.options.Latency {
			retProbe := &manager.Probe{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          escapedName,
					EBPFSection:  "kretprobe/utrace",
					EBPFFuncName: "kretprobe_utrace",
				},
				CopyProgram:   true,
				MatchFuncName: fmt.Sprintf(`^%s$`, escapedName),
			}
			u.manager.Probes = append(u.manager.Probes, retProbe)
			oneOfSelector.Selectors = append(oneOfSelector.Selectors, &manager.ProbeSelector{
				ProbeIdentificationPair: retProbe.ProbeIdentificationPair,
			})
			constantEditors = append(constantEditors, manager.ConstantEditor{
				Name:  "func_id",
				Value: uint64(funcID),
				ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
					retProbe.ProbeIdentificationPair,
				},
			})
			if len(u.options.Binary) > 0 || u.options.PIDFilter > 0 {
				constantEditors = append(constantEditors, manager.ConstantEditor{
					Name:  "filter_user_binary",
					Value: uint64(1),
					ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
						retProbe.ProbeIdentificationPair,
					},
				})
			}
		}

		u.matchingFuncCache[funcID] = sym
		u.symbolNameToFuncID[sym.Name] = funcID
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

// ResolveUserSymbolAndOffset returns the symbol of the function in which a given address lives, as well as the offset
// inside that function
func (u *UTrace) ResolveUserSymbolAndOffset(address SymbolAddr) StackTraceNode {
	for symbolAddr, symbol := range u.symbolsCache {
		if address >= symbolAddr && address < symbolAddr+SymbolAddr(symbol.Size) {
			funcID, ok := u.symbolNameToFuncID[symbol.Name]
			if !ok {
				funcID = -1
			}
			return StackTraceNode{
				Type:   User,
				Symbol: symbol,
				FuncID: funcID,
				Offset: address - symbolAddr,
			}
		}
	}
	return StackTraceNode{
		Type:   User,
		Symbol: UserSymbolNotFound,
		FuncID: -1,
		Offset: address,
	}
}

// ResolveKernelSymbolAndOffset returns the symbol of the kernel function in which a given address lives, as well as
// the offset inside that function
func (u *UTrace) ResolveKernelSymbolAndOffset(address SymbolAddr) StackTraceNode {
	for symbolAddr, symbol := range u.kallsymsCache {
		if address >= symbolAddr && address < symbolAddr+SymbolAddr(symbol.Size) {
			funcID, ok := u.symbolNameToFuncID[symbol.Name]
			if !ok {
				funcID = -1
			}
			return StackTraceNode{
				Type:   Kernel,
				Symbol: symbol,
				FuncID: funcID,
				Offset: address - symbolAddr,
			}
		}
	}
	return StackTraceNode{
		Type:   Kernel,
		Symbol: KernelSymbolNotFound,
		FuncID: -1,
		Offset: address,
	}
}

// TraceEventsHandler handles perf events from the kernel
func (u *UTrace) TraceEventsHandler(Cpu int, data []byte, perfMap *manager.PerfMap, m *manager.Manager) {
	var evt TraceEvent
	_, err := evt.UnmarshalBinary(data)
	if err != nil {
		logrus.Warnf("couldn't parse data (%d): %v", len(data), err)
		return
	}

	// parse the collected stack straces
	userTrace := make([]SymbolAddr, 127)
	kernelTrace := make([]SymbolAddr, 127)
	if evt.UserStackID > 0 {
		if err := u.stackTraces.Lookup(evt.UserStackID, userTrace); err != nil {
			logrus.Warnf("couldn't find stack trace %d: %v", evt.UserStackID, err)
			atomic.AddUint64(&u.userStackTraceLost, 1)
		} else {
			atomic.AddUint64(&u.userStackTraceCounter, 1)
		}
	}
	if evt.KernelStackID > 0 {
		if err := u.stackTraces.Lookup(evt.KernelStackID, kernelTrace); err != nil {
			logrus.Warnf("couldn't find stack trace %d: %v", evt.KernelStackID, err)
			atomic.AddUint64(&u.kernelStackTraceLost, 1)
		} else {
			atomic.AddUint64(&u.kernelStackTraceCounter, 1)
		}
	}

	// fetch existing stack traces
	stackTraces, ok := u.matchingFuncStackTraces[evt.FuncID]
	if !ok {
		stackTraces = make(map[CombinedID]*StackTrace)
		u.matchingFuncStackTraces[evt.FuncID] = stackTraces
	}

	// only resolve the stack trace if this is a new one
	combinedID := CombinedID(evt.UserStackID)<<32 + CombinedID(evt.KernelStackID)
	stackTrace, ok := stackTraces[combinedID]
	if ok {
		stackTrace.Count += 1
		return
	}

	// create new stack trace
	stackTrace = NewStackTrace(1)

	// resolve user stack trace
	for _, addr := range userTrace {
		if addr == 0 {
			break
		}
		stackTrace.UserStacktrace = append(stackTrace.UserStacktrace, u.ResolveUserSymbolAndOffset(addr))
	}

	// resolve kernel stack trace
	for _, addr := range kernelTrace {
		if addr == 0 {
			break
		}
		stackTrace.KernelStackTrace = append(stackTrace.KernelStackTrace, u.ResolveKernelSymbolAndOffset(addr))
	}
	// sometimes the kernel does not prepend the traced function in the stack trace. Add it now.
	if len(stackTrace.KernelStackTrace) > 0 && stackTrace.KernelStackTrace[0].FuncID != evt.FuncID {
		stackTrace.KernelStackTrace = append([]StackTraceNode{
			{
				Type:   Kernel,
				FuncID: evt.FuncID,
				Symbol: u.matchingFuncCache[evt.FuncID],
				Offset: 0,
			}}, stackTrace.KernelStackTrace...)
	}

	stackTraces[combinedID] = stackTrace
}
