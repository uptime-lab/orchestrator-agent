package handlers

import "testing"

// The gradient is the operator-facing contract: cool is GREEN, the midpoint
// is yellow, hot is RED, and out-of-range values clamp instead of wrapping.
func TestGradientColorEndpoints(t *testing.T) {
	cases := []struct {
		name string
		v    float64
		want [3]uint8
	}{
		{"cold clamps green", 20, [3]uint8{0, ledAmbientMax, 0}},
		{"low edge green", 45, [3]uint8{0, ledAmbientMax, 0}},
		{"midpoint yellow", 62.5, [3]uint8{ledAmbientMax, ledAmbientMax, 0}},
		{"high edge red", 80, [3]uint8{ledAmbientMax, 0, 0}},
		{"hot clamps red", 120, [3]uint8{ledAmbientMax, 0, 0}},
	}
	for _, c := range cases {
		if got := gradientColor(c.v, 45, 80); got != c.want {
			t.Errorf("%s: gradientColor(%v) = %v, want %v", c.name, c.v, got, c.want)
		}
	}
}

// Blue must never appear in ambient colors: blue is identify's color, and the
// two must stay distinguishable at a glance across the whole gradient.
func TestGradientColorNeverBlue(t *testing.T) {
	for v := 0.0; v <= 150; v += 0.5 {
		if c := gradientColor(v, 45, 80); c[2] != 0 {
			t.Fatalf("gradientColor(%v) has blue=%d", v, c[2])
		}
	}
}

// An unknown source renders dark, never a stale or random color — the
// platform validates sources, but the agent can meet a newer platform.
func TestRenderIndicationUnknownSourceIsDark(t *testing.T) {
	var idle, total uint64
	colors := renderIndication(specsFromSources([]string{"off", "sparkle"}), &idle, &total)
	for i, c := range colors {
		if c != [3]uint8{0, 0, 0} {
			t.Errorf("led %d: %v, want dark", i, c)
		}
	}
}

// The first busy sample has no baseline and must report idle, not a spike.
func TestReadCPUBusyFirstSampleIsZero(t *testing.T) {
	var idle, total uint64
	if v := readCPUBusy(&idle, &total); v != 0 {
		t.Errorf("first sample = %v, want 0", v)
	}
}

// LED v2: absent Low/High/Brightness fall to the per-source defaults, so a
// spec naming only a source behaves exactly as v1 did.
func TestLedSpecDefaults(t *testing.T) {
	lo, hi := (ledSpec{Source: "temperature"}).bounds()
	if lo != 45 || hi != 80 {
		t.Fatalf("temperature defaults = %v..%v, want 45..80", lo, hi)
	}
	lo, hi = (ledSpec{Source: "ram"}).bounds()
	if lo != 0 || hi != 100 {
		t.Fatalf("ram defaults = %v..%v, want 0..100", lo, hi)
	}
	lo, hi = (ledSpec{Source: "temperature", Low: 40, High: 70}).bounds()
	if lo != 40 || hi != 70 {
		t.Fatalf("explicit bounds = %v..%v, want 40..70", lo, hi)
	}
	if s := (ledSpec{}).scale(); s != ledAmbientMax {
		t.Fatalf("default scale = %v, want %v", s, float64(ledAmbientMax))
	}
	if s := (ledSpec{Brightness: 100}).scale(); s != 255 {
		t.Fatalf("full brightness scale = %v, want 255", s)
	}
}

// The advertisement and the renderer must not drift: every advertised source
// renders something (registry rule), and off stays unadvertised.
func TestAdvertisedSourcesAllRender(t *testing.T) {
	var idle, total uint64
	specs := specsFromSources(LEDSupportedSources())
	colors := renderIndication(specs, &idle, &total)
	if len(colors) != len(specs) {
		t.Fatalf("renderIndication dropped an advertised source")
	}
	for _, src := range LEDSupportedSources() {
		if src == "off" {
			t.Fatal("off is a placeholder, not a renderable source")
		}
	}
}
