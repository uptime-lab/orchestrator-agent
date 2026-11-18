package handlers

import (
	"fmt"
	"os"
	"strings"
)

// Ambient-indication rendering, kept build-tag-free so the color math is unit
// tested on every platform.

// ledAmbientMax is the ambient brightness ceiling (~20% of full), the blade
// doc's own default — full-white ambient LEDs in a rack are the problem this
// feature solves.
const ledAmbientMax = 50

// ledSpec parameterizes one digital LED (LED v2). Zero Low/High/Brightness
// fall to the per-source defaults below, so a spec naming only a source
// behaves exactly as v1 did.
type ledSpec struct {
	Source     string  `json:"source"`
	Low        float64 `json:"low,omitempty"`
	High       float64 `json:"high,omitempty"`
	Brightness int     `json:"brightness,omitempty"`
}

// LEDSupportedSources is the reader registry's advertisement, sent in
// ConnectionInit so the platform offers exactly what this agent can render.
// Extending renderIndication with a new source means extending THIS list in
// the same change — the advertisement is the only thing the platform trusts.
func LEDSupportedSources() []string {
	return []string{"temperature", "load", "ram", "disk"}
}

// specsFromSources lifts a v1 source list into specs (defaults everywhere) —
// one render path, not two.
func specsFromSources(sources []string) []ledSpec {
	specs := make([]ledSpec, len(sources))
	for i, src := range sources {
		specs[i] = ledSpec{Source: src}
	}
	return specs
}

// defaults per source: temperature 45..80 °C, percentage sources 0..100.
func (s ledSpec) bounds() (float64, float64) {
	if s.Low != 0 || s.High != 0 {
		return s.Low, s.High
	}
	if s.Source == "temperature" {
		return 45, 80
	}
	return 0, 100
}

// scale returns the brightness ceiling for this LED (0 = the v1 default).
func (s ledSpec) scale() float64 {
	if s.Brightness <= 0 || s.Brightness > 100 {
		return ledAmbientMax
	}
	return float64(s.Brightness) * 255 / 100
}

// renderIndication maps each LED's spec to a color via its metric reader.
// Unknown/off sources render dark.
func renderIndication(specs []ledSpec, prevIdle, prevTotal *uint64) [][3]uint8 {
	colors := make([][3]uint8, len(specs))
	for i, spec := range specs {
		lo, hi := spec.bounds()
		var value float64
		switch spec.Source {
		case "temperature":
			value = readSoCTemp()
		case "load":
			value = readCPUBusy(prevIdle, prevTotal) * 100
		case "ram":
			value = readRAMUsedPercent()
		case "disk":
			value = readDiskUsedPercent()
		default:
			colors[i] = [3]uint8{0, 0, 0}
			continue
		}
		colors[i] = gradientColorScaled(value, lo, hi, spec.scale())
	}
	return colors
}

// gradientColor lerps green -> yellow -> red across [lo, hi], bounded, at
// the v1 brightness.
func gradientColor(v, lo, hi float64) [3]uint8 {
	return gradientColorScaled(v, lo, hi, ledAmbientMax)
}

// gradientColorScaled is gradientColor with a caller-chosen brightness
// ceiling (LED v2's per-LED brightness).
func gradientColorScaled(v, lo, hi, max float64) [3]uint8 {
	t := (v - lo) / (hi - lo)
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	var r, g float64
	if t < 0.5 {
		r, g = t*2, 1 // green -> yellow
	} else {
		r, g = 1, (1-t)*2 // yellow -> red
	}
	return [3]uint8{uint8(r * max), uint8(g * max), 0}
}

// readRAMUsedPercent returns used memory as a percentage (0 on error ->
// renders green), from /proc/meminfo's MemTotal/MemAvailable — the same
// definition `free` uses for "used".
func readRAMUsedPercent() float64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var totalKB, availKB float64
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(v), "%f", &totalKB)
		}
		if v, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(v), "%f", &availKB)
		}
	}
	if totalKB <= 0 || availKB < 0 {
		return 0
	}
	return (totalKB - availKB) / totalKB * 100
}

// readSoCTemp returns the SoC temperature in °C (0 on error -> renders green).
func readSoCTemp() float64 {
	raw, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0
	}
	var milli int64
	_, _ = fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &milli)
	return float64(milli) / 1000
}

// readCPUBusy returns the busy fraction (0..1) since the previous call,
// computed from /proc/stat's aggregate line — a real utilization sample over
// the indication period, not the 1-minute load average.
func readCPUBusy(prevIdle, prevTotal *uint64) float64 {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i, f := range fields[1:] {
		var v uint64
		_, _ = fmt.Sscanf(f, "%d", &v)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	dTotal, dIdle := total-*prevTotal, idle-*prevIdle
	first := *prevTotal == 0
	*prevTotal, *prevIdle = total, idle
	if first || dTotal == 0 {
		return 0
	}
	return 1 - float64(dIdle)/float64(dTotal)
}
