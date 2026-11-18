//go:build linux

package hardware

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// MetricsReader samples live resource utilization from /proc and /sys. It is
// stateful: CPU% needs the delta between two /proc/stat reads, so the previous
// aggregate snapshot is kept between calls.
type MetricsReader struct {
	logger  *slog.Logger
	prevCPU *cpuTimes
}

func NewMetricsReader(logger *slog.Logger) *MetricsReader {
	return &MetricsReader{logger: logger.With("component", "metrics_reader")}
}

type cpuTimes struct {
	idle  uint64
	total uint64
}

// Read produces a metrics sample. The first call has no previous CPU snapshot,
// so cpu_percent is reported as 0 until the next tick establishes a delta.
func (r *MetricsReader) Read() *proto.MetricsUpdate {
	m := &proto.MetricsUpdate{Timestamp: time.Now().Unix()}

	if cur, ok := readCPUTimes(); ok {
		if r.prevCPU != nil {
			m.CpuPercent = cpuPercent(*r.prevCPU, cur)
		}
		r.prevCPU = &cur
	}

	if total, used, avail, ok := readMem(); ok {
		m.MemTotalBytes = total
		m.MemUsedBytes = used
		m.MemAvailableBytes = avail
	}

	if l1, l5, l15, ok := readLoadAvg(); ok {
		m.LoadAvg_1 = l1
		m.LoadAvg_5 = l5
		m.LoadAvg_15 = l15
	}

	m.Thermal = readThermal()
	return m
}

// readCPUTimes parses the aggregate "cpu" line of /proc/stat into idle vs total
// jiffies.
func readCPUTimes() (cpuTimes, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // user nice system idle iowait irq softirq steal ...
		var total, idle uint64
		for i, f := range fields {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				continue
			}
			total += v
			if i == 3 || i == 4 { // idle + iowait count as idle time
				idle += v
			}
		}
		return cpuTimes{idle: idle, total: total}, true
	}
	return cpuTimes{}, false
}

func cpuPercent(prev, cur cpuTimes) float64 {
	totalDelta := float64(cur.total - prev.total)
	idleDelta := float64(cur.idle - prev.idle)
	if totalDelta <= 0 {
		return 0
	}
	pct := (1 - idleDelta/totalDelta) * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

// readMem parses /proc/meminfo (values are in kB). Used = total - available.
func readMem() (total, used, available uint64, ok bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, false
	}
	var memTotal, memAvail uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotal = v * 1024
		case "MemAvailable:":
			memAvail = v * 1024
		}
	}
	if memTotal == 0 {
		return 0, 0, 0, false
	}
	if memAvail > memTotal {
		memAvail = memTotal
	}
	return memTotal, memTotal - memAvail, memAvail, true
}

func readLoadAvg() (l1, l5, l15 float64, ok bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	l1, _ = strconv.ParseFloat(fields[0], 64)
	l5, _ = strconv.ParseFloat(fields[1], 64)
	l15, _ = strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15, true
}

// readThermal reads each /sys/class/thermal/thermal_zone*/temp (milli-degrees C)
// with its type name. Returns an empty slice when no sensors are present.
func readThermal() []*proto.ThermalZone {
	entries, err := os.ReadDir("/sys/class/thermal")
	if err != nil {
		return nil
	}
	var zones []*proto.ThermalZone
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		base := "/sys/class/thermal/" + e.Name()
		raw, err := os.ReadFile(base + "/temp")
		if err != nil {
			continue
		}
		milli, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			continue
		}
		name := e.Name()
		if t, err := os.ReadFile(base + "/type"); err == nil {
			name = strings.TrimSpace(string(t))
		}
		zones = append(zones, &proto.ThermalZone{
			Name:        name,
			TempCelsius: float64(milli) / 1000.0,
		})
	}
	return zones
}
