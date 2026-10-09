// Package metrics reads real host measurements from procfs. Nothing here is
// estimated: every value is a kernel counter or a current kernel reading.
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// NetCounters are cumulative interface counters from /proc/net/dev.
type NetCounters struct {
	RxBytes, RxPackets, RxDrops uint64
	TxBytes, TxPackets, TxDrops uint64
}

// CPUTimes are cumulative jiffies from the aggregate "cpu" line of /proc/stat.
type CPUTimes struct {
	Total, Idle uint64
}

// MemInfo is the memory state from /proc/meminfo, in bytes.
type MemInfo struct {
	Total, Available uint64
}

// ReadNetDev parses /proc/net/dev. Loopback is excluded.
func ReadNetDev(r io.Reader) (map[string]NetCounters, error) {
	out := map[string]NetCounters{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			return nil, fmt.Errorf("net/dev: Zeile für %s hat %d Felder", name, len(f))
		}
		v, err := parseUints(f[:16])
		if err != nil {
			return nil, fmt.Errorf("net/dev %s: %w", name, err)
		}
		out[name] = NetCounters{
			RxBytes: v[0], RxPackets: v[1], RxDrops: v[3],
			TxBytes: v[8], TxPackets: v[9], TxDrops: v[11],
		}
	}
	return out, sc.Err()
}

// ReadCPU parses the aggregate cpu line of /proc/stat.
func ReadCPU(r io.Reader) (CPUTimes, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		v, err := parseUints(f[1:])
		if err != nil {
			return CPUTimes{}, fmt.Errorf("stat: %w", err)
		}
		var total uint64
		for _, x := range v {
			total += x
		}
		idle := v[3]
		if len(v) > 4 {
			idle += v[4] // iowait counts as idle
		}
		return CPUTimes{Total: total, Idle: idle}, nil
	}
	return CPUTimes{}, fmt.Errorf("stat: keine cpu-Zeile gefunden")
}

// ReadMem parses MemTotal and MemAvailable from /proc/meminfo.
func ReadMem(r io.Reader) (MemInfo, error) {
	var m MemInfo
	var gotTotal, gotAvail bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return m, err
			}
			m.Total, gotTotal = v*1024, true
		case "MemAvailable:":
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return m, err
			}
			m.Available, gotAvail = v*1024, true
		}
	}
	if !gotTotal || !gotAvail {
		return m, fmt.Errorf("meminfo: MemTotal oder MemAvailable fehlt")
	}
	return m, nil
}

// CPUPercent returns busy percentage between two readings.
func CPUPercent(prev, cur CPUTimes) float64 {
	dt := float64(cur.Total - prev.Total)
	if dt <= 0 {
		return 0
	}
	di := float64(cur.Idle - prev.Idle)
	return 100 * (1 - di/dt)
}

// MemUsedPercent returns used memory percentage.
func (m MemInfo) MemUsedPercent() float64 {
	if m.Total == 0 {
		return 0
	}
	return 100 * float64(m.Total-m.Available) / float64(m.Total)
}

// Files for live reads; tests inject other readers.
const (
	ProcNetDev = "/proc/net/dev"
	ProcStat   = "/proc/stat"
	ProcMem    = "/proc/meminfo"
)

// ReadFile opens a procfs path and applies parse.
func ReadFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	return parse(f)
}

func parseUints(fields []string) ([]uint64, error) {
	out := make([]uint64, len(fields))
	for i, s := range fields {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
