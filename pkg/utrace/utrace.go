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
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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
	options           Options
	kernelCountersMap *ebpf.Map
	stackTracesMap    *ebpf.Map
	binaryPathMap     *ebpf.Map
	lostCountMap      *ebpf.Map
	tracedPIDsMap     *ebpf.Map
	manager           *manager.Manager
	managerOptions    manager.Options
	startTime         time.Time
	funcIDCursor      FuncID

	// kallsymsCache contains the kernel symbols parsed from /proc/kallsyms
	kallsymsCache map[SymbolAddr]elf.Symbol
	// kernelSymbolNameToFuncID contains the FuncID attributed to each kernel symbol
	kernelSymbolNameToFuncID map[string]FuncID

	// funcCache holds the traced symbol associated to each FuncID (kernel and userspace)
	funcCache map[FuncID]TracedSymbol
	// stackTraces holds the list of collected stack traces for all FuncID (kernel and unserspace)
	stackTraces map[FuncID]map[CombinedID]*StackTrace

	// TracedBinaries is the list of userspace binaries for which we are collecting stack traces
	TracedBinaries map[BinaryCookie]*TracedBinary

	kernelStackTraceCounter uint64
	kernelStackTraceLost    uint64
	userStackTraceCounter   uint64
	userStackTraceLost      uint64
}

// NewUTrace creates a new UTrace instance
func NewUTrace(options Options) *UTrace {
	return &UTrace{
		options:                  options,
		funcCache:                make(map[FuncID]TracedSymbol),
		kernelSymbolNameToFuncID: make(map[string]FuncID),
		kallsymsCache:            make(map[SymbolAddr]elf.Symbol),
		stackTraces:              make(map[FuncID]map[CombinedID]*StackTrace),
		TracedBinaries:           make(map[BinaryCookie]*TracedBinary),
	}
}

// Start hooks on the requested symbols and begins tracing
func (u *UTrace) Start() error {
	// ensure that at least one function pattern was provided
	if u.options.FuncPattern == nil && u.options.KernelFuncPattern == nil && len(u.options.Tracepoints) == 0 && len(u.options.PerfEvents) == 0 {
		return NoPatternProvidedErr
	}

	if err := u.start(); err != nil {
		return err
	}

	logrus.Infof("Tracing started on %d symbols ... (Ctrl + C to stop)", len(u.funcCache))
	return nil
}

// dump dumps the the statistiques collected by UTrace
func (u *UTrace) dump() (Report, error) {
	report := NewReport(time.Now().Sub(u.startTime))
	var id FuncID
	stats := make([]kernelCounter, runtime.NumCPU())
	iterator := u.kernelCountersMap.Iterate()

	for iterator.Next(&id, &stats) {
		symbol, ok := u.funcCache[id]
		if !ok {
			continue
		}
		f := NewFunc(symbol.symbol, symbol.binary)
		for _, cpuStat := range stats {
			f.Count += cpuStat.Count
			f.AverageLatency += time.Duration(cpuStat.CumulatedTime) * time.Nanosecond
		}
		if f.Count > 0 {
			f.AverageLatency = time.Duration(float64(f.AverageLatency.Nanoseconds()) / float64(f.Count))
		}

		f.stackTraces = u.stackTraces[id]

		report.functions[id] = f
	}

	// fetch counters
	report.stackTracerCount.Kernel = atomic.LoadUint64(&u.kernelStackTraceCounter)
	report.stackTracerCount.User = atomic.LoadUint64(&u.userStackTraceCounter)
	if err := u.lostCountMap.Lookup([4]byte{0}, &report.stackTracerCount.LostUser); err != nil {
		logrus.Warnf("failed to retrieve user stack trace lost count: %s", err)
	}
	if err := u.lostCountMap.Lookup([4]byte{1}, &report.stackTracerCount.LostKernel); err != nil {
		logrus.Warnf("failed to retrieve kernel stack trace lost count: %s", err)
	}
	report.stackTracerCount.LostUser += atomic.LoadUint64(&u.userStackTraceLost)
	report.stackTracerCount.LostKernel += atomic.LoadUint64(&u.kernelStackTraceLost)
	return report, iterator.Err()
}

// Stop shuts down UTrace
func (u *UTrace) Stop() (Report, error) {
	// stop all probes
	for _, probe := range u.manager.Probes {
		_ = probe.Stop()
	}

	// sleep until the perf map is empty
	logrus.Infof("flushing the remaining events in the perf map ...")
	var done bool
	var lastCount uint64
	for !done {
		lastCount = atomic.LoadUint64(&u.kernelStackTraceCounter) + atomic.LoadUint64(&u.userStackTraceCounter)
		time.Sleep(1 * time.Second)
		if lastCount == atomic.LoadUint64(&u.kernelStackTraceCounter)+atomic.LoadUint64(&u.userStackTraceCounter) {
			done = true
		}
	}

	// dump
	dump, err := u.dump()
	// Close the manager
	_ = errors.Wrap(u.manager.Stop(manager.CleanAll), "couldn't stop manager")
	return dump, err
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
	u.kernelCountersMap, _, err = u.manager.GetMap("counters")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/counters")
	}

	u.stackTracesMap, _, err = u.manager.GetMap("stack_traces")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/stack_traces")
	}

	u.binaryPathMap, _, err = u.manager.GetMap("binary_path")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/binary_path")
	}

	u.lostCountMap, _, err = u.manager.GetMap("lost_traces")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/lost_traces")
	}

	u.tracedPIDsMap, _, err = u.manager.GetMap("traced_pids")
	if err != nil {
		_ = u.manager.Stop(manager.CleanAll)
		return errors.Wrap(err, "couldn't find maps/traced_pids")
	}
	return nil
}

func (u *UTrace) insertTracedBinary(path string, pid int) error {
	// fetch the binary file inode
	fileinfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("couldn't load %s: %v", path, err)
	}

	resolvedPath, err := os.Readlink(path)
	if err != nil {
		resolvedPath = ""
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("couldn't load %s: %v", path, err)
	}

	// check if the file has been seen before
	for _, tracedBinary := range u.TracedBinaries {
		// an inode conflict is technically possible between multiple mount points, but checking the binary size and
		// the inode makes it relatively unlikely, and is less overkill than hashing the file. (we don't want to check
		// the path, or even the resolved paths because of hard link collisions)
		if stat.Ino == tracedBinary.Inode && stat.Size == tracedBinary.Size {
			// if a pid is provided, this means that we filter the events from this binary by pid, add it to the list
			if pid != 0 {
				tracedBinary.Pids = append(tracedBinary.Pids, pid)
			}
			return nil
		}
	}

	// if we reach this point, this is a new entry, add it to the list and generate a cookie
	cookie := rand.Uint32()
	for _, ok = u.TracedBinaries[BinaryCookie(cookie)]; ok; {
		cookie = rand.Uint32()
	}
	entry := TracedBinary{
		Path:               path,
		ResolvedPath:       resolvedPath,
		Inode:              stat.Ino,
		Size:               stat.Size,
		Cookie:             BinaryCookie(cookie),
		symbolsCache:       make(map[SymbolAddr]elf.Symbol),
		symbolNameToFuncID: make(map[string]FuncID),
	}
	if pid > 0 {
		entry.Pids = []int{pid}
	}

	// fetch the list of symbols of the binary
	f, syms, err := manager.OpenAndListSymbols(entry.Path)
	if err != nil {
		return err
	}

	entry.file = f
	for _, sym := range syms {
		entry.symbolsCache[SymbolAddr(sym.Value)] = sym
	}

	u.TracedBinaries[entry.Cookie] = &entry
	return nil
}

func (u *UTrace) generateTracedBinaries() error {
	var err error
	for _, binary := range u.options.Binary {
		if err = u.insertTracedBinary(binary, 0); err != nil {
			return err
		}
	}

	for _, pid := range u.options.PIDFilter {
		if err = u.insertTracedBinary(fmt.Sprintf("/proc/%d/exe", pid), pid); err != nil {
			return err
		}
	}
	return nil
}

func (u *UTrace) start() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return fmt.Errorf("couldn't find asset: %w", err)
	}

	// setup a default manager
	u.setupDefaultManager()

	if err = u.generateTracedBinaries(); err != nil {
		return fmt.Errorf("couldn't generate the list of traced binaries: %w", err)
	}

	// generate uprobes if a binary file is provided
	if u.options.FuncPattern != nil {
		for _, binary := range u.TracedBinaries {
			if err = u.generateUProbes(binary); err != nil {
				return fmt.Errorf("couldn't generate uprobes: %w", err)
			}
		}
	}

	// setup kprobes if a kernel function pattern was provided
	if u.options.KernelFuncPattern != nil {
		if err = u.generateKProbes(); err != nil {
			return fmt.Errorf("couldn't generate kprobes: %w", err)
		}
	}

	// setup tracepoint probes
	if len(u.options.Tracepoints) > 0 {
		if err = u.generateTracepoints(); err != nil {
			return fmt.Errorf("couldn't generate tracepoints: %w", err)
		}
	}

	// setup perf events
	if len(u.options.PerfEvents) > 0 {
		if len(u.TracedBinaries) == 0 {
			if err = u.generatePerfEvents(nil); err != nil {
				return fmt.Errorf("couldn't generate perf events: %w", err)
			}
		} else {
			for _, binary := range u.TracedBinaries {
				if err = u.generatePerfEvents(binary); err != nil {
					return fmt.Errorf("couldn't generate perf events: %w", err)
				}
			}
		}
	}

	if len(u.funcCache) == 0 {
		return fmt.Errorf("nothing matched the provided pattern(s)")
	}

	u.managerOptions.MapSpecEditors["counters"] = manager.MapSpecEditor{
		Type:       ebpf.PerCPUArray,
		MaxEntries: uint32(len(u.funcCache)),
		EditorFlag: manager.EditMaxEntries,
	}

	// initialize the manager
	if err = u.manager.InitWithOptions(bytes.NewReader(buf), u.managerOptions); err != nil {
		return fmt.Errorf("couldn't init manager: %w", err)
	}

	// select kernel space maps
	if err = u.selectMaps(); err != nil {
		return err
	}

	// push kernel filters
	if err = u.pushKernelFilters(); err != nil {
		return err
	}

	// start the manager
	if err = u.manager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start manager")
	}

	u.startTime = time.Now()
	return nil
}

func (u *UTrace) pushKernelFilters() error {
	// insert binary path in kernel space to track binary executions
	for cookie, binary := range u.TracedBinaries {
		if len(binary.Pids) == 0 {
			// track process executions using the binary path
			pathB := [PathMax]byte{}
			copy(pathB[:], binary.Path)
			if err := u.binaryPathMap.Put(pathB, uint32(cookie)); err != nil {
				_ = u.manager.Stop(manager.CleanAll)
				return fmt.Errorf("failed to insert binary path %s in kernel space: %w", binary.Path, err)
			}
		} else {
			// we're tracking specific pids, insert them now
			for _, pid := range binary.Pids {
				if err := u.tracedPIDsMap.Put(uint32(pid), uint32(binary.Cookie)); err != nil {
					_ = u.manager.Stop(manager.CleanAll)
					return fmt.Errorf("failed to insert PID filter for binary %s: %w", binary.Path, err)
				}
			}
		}
	}
	return nil
}

func (u *UTrace) generateUProbes(binary *TracedBinary) error {
	if u.options.FuncPattern == nil || binary == nil {
		return nil
	}

	// from the entire list of symbols, only keep the functions that match the provided pattern
	var matches []elf.Symbol
	for _, sym := range binary.symbolsCache {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && u.options.FuncPattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if uint32(len(matches)) > MaxUserSymbolsCount {
		logrus.Warnf("%d symbols matched the provided pattern, only the first %d symbols will be traced.", len(matches), MaxUserSymbolsCount)
		matches = matches[0:MaxUserSymbolsCount]
	}

	if len(matches) == 0 {
		return fmt.Errorf("no symbol in '%s' match the provided pattern '%s'", binary.Path, u.options.FuncPattern.String())
	}

	// relocate the function address with the base address of the binary
	manager.SanitizeUprobeAddresses(binary.file, matches)

	// generate a probe for each traced PID, or a generic one that will match all pids
	tracedPIDs := binary.Pids[:]
	if len(tracedPIDs) == 0 {
		tracedPIDs = []int{0}
	}

	var oneOfSelector manager.OneOf
	var constantEditors []manager.ConstantEditor

	// configure a probe for each symbol we're going to hook onto
	for _, sym := range matches {
		escapedName := sanitizeFuncName(sym.Name)
		funcID := u.nextFuncID()

		for _, pid := range tracedPIDs {
			probeUID := RandomStringWithLen(10)
			probe := &manager.Probe{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          probeUID,
					EBPFSection:  "uprobe/utrace",
					EBPFFuncName: "uprobe_utrace",
				},
				CopyProgram:   true,
				BinaryPath:    binary.Path,
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
			if pid > 0 {
				probe.PerfEventPID = pid
			}

			if u.options.Latency {
				retProbe := &manager.Probe{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						UID:          probeUID,
						EBPFSection:  "uretprobe/utrace",
						EBPFFuncName: "uretprobe_utrace",
					},
					CopyProgram:   true,
					BinaryPath:    binary.Path,
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
				if pid > 0 {
					retProbe.PerfEventPID = pid
				}
			}

			u.funcCache[funcID] = TracedSymbol{symbol: sym, binary: binary}
			binary.symbolNameToFuncID[sym.Name] = funcID
		}
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

func (u *UTrace) parseKallsyms() error {
	if len(u.kallsymsCache) > 0 {
		// this has already been done
		return nil
	}

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
		probeUID := RandomStringWithLen(10)
		probe := &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          probeUID,
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
		if len(u.options.Binary) > 0 || len(u.options.PIDFilter) > 0 {
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
					UID:          probeUID,
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
			if len(u.options.Binary) > 0 || len(u.options.PIDFilter) > 0 {
				constantEditors = append(constantEditors, manager.ConstantEditor{
					Name:  "filter_user_binary",
					Value: uint64(1),
					ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
						retProbe.ProbeIdentificationPair,
					},
				})
			}
		}

		u.funcCache[funcID] = TracedSymbol{symbol: sym}
		u.kernelSymbolNameToFuncID[sym.Name] = funcID
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

func (u *UTrace) generateTracepoints() error {
	if err := u.parseKallsyms(); err != nil {
		return errors.Wrap(err, "couldn't parse /proc/kallsyms")
	}

	if uint32(len(u.options.Tracepoints)) > MaxKernelSymbolsCount {
		logrus.Warnf("only the first %d tracepoints will be traced (out of %d)", MaxKernelSymbolsCount, len(u.options.Tracepoints))
		u.options.Tracepoints = u.options.Tracepoints[0:MaxKernelSymbolsCount]
	}

	// configure a probe for each tracepoint we're going to hook onto
	var oneOfSelector manager.OneOf
	var constantEditors []manager.ConstantEditor

	for _, tracepoint := range u.options.Tracepoints {
		funcID := u.nextFuncID()
		probeUID := RandomStringWithLen(10)

		tpDef := strings.Split(tracepoint, ":")
		if len(tpDef) != 2 {
			return fmt.Errorf("'%s' isn't a valid tracepoint (expected format is [category]:[name])", tracepoint)
		}

		probe := &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          probeUID,
				EBPFSection:  "tracepoint/utrace",
				EBPFFuncName: "tracepoint_utrace",
			},
			CopyProgram:        true,
			TracepointCategory: tpDef[0],
			TracepointName:     tpDef[1],
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
		if len(u.options.Binary) > 0 || len(u.options.PIDFilter) > 0 {
			constantEditors = append(constantEditors, manager.ConstantEditor{
				Name:  "filter_user_binary",
				Value: uint64(1),
				ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
					probe.ProbeIdentificationPair,
				},
			})
		}

		// 0xffffffff00000001 is a fake value inserted to make sure that the tracepoint is part of the kernel stack trace
		u.funcCache[funcID] = TracedSymbol{symbol: elf.Symbol{Name: tracepoint, Value: 0xffffffff00000001}}
		u.kernelSymbolNameToFuncID[tracepoint] = funcID
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

func (u *UTrace) generatePerfEvents(binary *TracedBinary) error {
	if err := u.parseKallsyms(); err != nil {
		return errors.Wrap(err, "couldn't parse /proc/kallsyms")
	}

	if uint32(len(u.options.PerfEvents)) > MaxKernelSymbolsCount {
		logrus.Warnf("only the first %d perf events will be traced (out of %d)", MaxKernelSymbolsCount, len(u.options.PerfEvents))
		u.options.PerfEvents = u.options.PerfEvents[0:MaxKernelSymbolsCount]
	}

	// generate a probe for each traced PID, or a generic one that will match all pids
	var tracedPIDs []int
	if binary != nil {
		tracedPIDs = binary.Pids[:]
	}
	if len(tracedPIDs) == 0 {
		tracedPIDs = []int{0}
	}

	// configure a probe for each tracepoint we're going to hook onto
	var oneOfSelector manager.OneOf
	var constantEditors []manager.ConstantEditor

	for _, perfEvent := range u.options.PerfEvents {
		funcID := u.nextFuncID()
		peDefRaw := strings.Split(perfEvent, ":")
		if len(peDefRaw) != 3 {
			return fmt.Errorf("'%s' isn't a valid perf event (expected format is [perf_event_type]:[perf_event_name]:[frequency])", perfEvent)
		}
		peType, err := strconv.Atoi(peDefRaw[0])
		if err != nil {
			return fmt.Errorf("'%s' isn't a valid perf event type (expected format is [perf_event_type]:[perf_event_name]:[frequency]): %w", peDefRaw[0], err)
		}
		peName, err := strconv.Atoi(peDefRaw[1])
		if err != nil {
			return fmt.Errorf("'%s' isn't a valid perf event name (expected format is [perf_event_type]:[perf_event_name]:[frequency]): %w", peDefRaw[1], err)
		}
		peFrequency, err := strconv.Atoi(peDefRaw[2])
		if err != nil {
			return fmt.Errorf("'%s' isn't a valid perf event frequency (expected format is [perf_event_type]:[perf_event_name]:[frequency]): %w", peDefRaw[2], err)
		}

		for _, pid := range tracedPIDs {
			probeUID := RandomStringWithLen(10)
			probe := &manager.Probe{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          probeUID,
					EBPFSection:  "perf_event/utrace",
					EBPFFuncName: "perf_event_utrace",
				},
				CopyProgram:     true,
				PerfEventType:   peType,
				PerfEventConfig: peName,
				SampleFrequency: peFrequency,
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
			if len(u.options.Binary) > 0 || len(u.options.PIDFilter) > 0 {
				if pid > 0 {
					probe.PerfEventPID = pid
				}
				constantEditors = append(constantEditors, manager.ConstantEditor{
					Name:  "filter_user_binary",
					Value: uint64(1),
					ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
						probe.ProbeIdentificationPair,
					},
				})
			}
		}

		// 0xffffffff00000001 is a fake value inserted to make sure that the tracepoint is part of the kernel stack trace
		u.funcCache[funcID] = TracedSymbol{symbol: elf.Symbol{Name: perfEvent, Value: 0xffffffff00000001}}
		u.kernelSymbolNameToFuncID[perfEvent] = funcID
	}

	u.managerOptions.ActivatedProbes = append(u.managerOptions.ActivatedProbes, &oneOfSelector)
	u.managerOptions.ConstantEditors = append(u.managerOptions.ConstantEditors, constantEditors...)

	return nil
}

// ResolveUserSymbolAndOffset returns the symbol of the function in which a given address lives, as well as the offset
// inside that function
func (u *UTrace) ResolveUserSymbolAndOffset(address SymbolAddr, binary *TracedBinary) StackTraceNode {
	if binary != nil {
		for symbolAddr, symbol := range binary.symbolsCache {
			if address >= symbolAddr && address < symbolAddr+SymbolAddr(symbol.Size) {
				funcID, ok := binary.symbolNameToFuncID[symbol.Name]
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
	}

	return StackTraceNode{
		Type:   User,
		Symbol: SymbolNotFound,
		FuncID: -1,
		Offset: address,
	}
}

// ResolveKernelSymbolAndOffset returns the symbol of the kernel function in which a given address lives, as well as
// the offset inside that function
func (u *UTrace) ResolveKernelSymbolAndOffset(address SymbolAddr) StackTraceNode {
	for symbolAddr, symbol := range u.kallsymsCache {
		if address >= symbolAddr && address < symbolAddr+SymbolAddr(symbol.Size) {
			funcID, ok := u.kernelSymbolNameToFuncID[symbol.Name]
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
		Symbol: SymbolNotFound,
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
		if err = u.stackTracesMap.Lookup(evt.UserStackID, userTrace); err != nil {
			logrus.Warnf("couldn't find stack trace %d: %v", evt.UserStackID, err)
			atomic.AddUint64(&u.userStackTraceLost, 1)
		} else {
			atomic.AddUint64(&u.userStackTraceCounter, 1)
		}
	}
	if evt.KernelStackID > 0 {
		if err = u.stackTracesMap.Lookup(evt.KernelStackID, kernelTrace); err != nil {
			logrus.Warnf("couldn't find stack trace %d: %v", evt.KernelStackID, err)
			atomic.AddUint64(&u.kernelStackTraceLost, 1)
		} else {
			atomic.AddUint64(&u.kernelStackTraceCounter, 1)
		}
	}

	// fetch existing stack traces
	stackTraces, ok := u.stackTraces[evt.FuncID]
	if !ok {
		stackTraces = make(map[CombinedID]*StackTrace)
		u.stackTraces[evt.FuncID] = stackTraces
	}

	// only resolve the stack trace if this is a new one
	combinedID := CombinedID(evt.UserStackID)<<32 + CombinedID(evt.KernelStackID)
	stackTrace, ok := stackTraces[combinedID]
	if ok {
		stackTrace.Count += 1
		return
	}

	// resolve binary
	binary := u.TracedBinaries[evt.Cookie]

	// create new stack trace
	stackTrace = NewStackTrace(1, binary)

	// resolve user stack trace
	for _, addr := range userTrace {
		if addr == 0 {
			break
		}
		stackTrace.UserStacktrace = append(stackTrace.UserStacktrace, u.ResolveUserSymbolAndOffset(addr, binary))
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
				Symbol: u.funcCache[evt.FuncID].symbol,
				Offset: 0,
			}}, stackTrace.KernelStackTrace...)
	}

	stackTraces[combinedID] = stackTrace
}
