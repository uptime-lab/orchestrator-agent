package handlers

import (
	"strings"
	"testing"
)

const configTxt = `# Please DO NOT modify this file
[all]
kernel=vmlinuz
arm_64bit=1

include usercfg.txt
`

func TestPatchManagedBlockAppend(t *testing.T) {
	out, err := patchManagedBlock([]byte(configTxt), "[cm5]\ndtparam=pciex1_gen=3\n[all]", "pcie")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "# Please DO NOT modify this file") {
		t.Errorf("original head lost:\n%s", s)
	}
	if !strings.Contains(s, "include usercfg.txt") {
		t.Errorf("original lines lost:\n%s", s)
	}
	want := "# >>> orchestrator:pcie >>>\n[cm5]\ndtparam=pciex1_gen=3\n[all]\n# <<< orchestrator:pcie <<<\n"
	if !strings.HasSuffix(s, want) {
		t.Errorf("block not appended at end:\n%s", s)
	}
}

func TestPatchManagedBlockIdempotentReplace(t *testing.T) {
	first, err := patchManagedBlock([]byte(configTxt), "arm_freq=2600", "overclock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := patchManagedBlock(first, "arm_freq=2800", "overclock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(second)
	if strings.Contains(s, "arm_freq=2600") {
		t.Errorf("old block content not replaced:\n%s", s)
	}
	if strings.Count(s, "# >>> orchestrator:overclock >>>") != 1 {
		t.Errorf("block duplicated:\n%s", s)
	}
	// Same input applied again must not change the file.
	third, err := patchManagedBlock(second, "arm_freq=2800", "overclock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(third) != s {
		t.Errorf("patch is not idempotent")
	}
}

func TestPatchManagedBlockIndependentMarkers(t *testing.T) {
	out, _ := patchManagedBlock([]byte(configTxt), "arm_freq=2800", "overclock")
	out, _ = patchManagedBlock(out, "dtparam=pciex1_gen=3", "pcie")
	out, err := patchManagedBlock(out, "arm_freq=3000", "overclock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "arm_freq=3000") || !strings.Contains(s, "dtparam=pciex1_gen=3") {
		t.Errorf("blocks interfered with each other:\n%s", s)
	}
	if strings.Contains(s, "arm_freq=2800") {
		t.Errorf("overclock block not replaced:\n%s", s)
	}
}

func TestPatchManagedBlockEmptyFileAndDefaults(t *testing.T) {
	out, err := patchManagedBlock(nil, "gpu_freq=750", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "# >>> orchestrator:orchestrator >>>\ngpu_freq=750\n# <<< orchestrator:orchestrator <<<\n"
	if string(out) != want {
		t.Errorf("unexpected output: %q", string(out))
	}
}

func TestPatchManagedBlockRefusesMalformedMarkers(t *testing.T) {
	broken := configTxt + "\n# >>> orchestrator:pcie >>>\ndtparam=pciex1_gen=3\n"
	if _, err := patchManagedBlock([]byte(broken), "x", "pcie"); err == nil {
		t.Fatal("expected error on begin-without-end markers")
	}
	inverted := "# <<< orchestrator:pcie <<<\nfoo\n# >>> orchestrator:pcie >>>\n"
	if _, err := patchManagedBlock([]byte(inverted), "x", "pcie"); err == nil {
		t.Fatal("expected error on inverted markers")
	}
}

func TestPatchManagedBlockRefusesDuplicatedMarkers(t *testing.T) {
	// Only the first pair would be rewritten, and config.txt's
	// last-assignment-wins semantics make the stale second copy the one the
	// firmware reads — a success report for settings the device never boots
	// with.
	dup := "# >>> orchestrator:pcie >>>\na=1\n# <<< orchestrator:pcie <<<\n" +
		"# >>> orchestrator:pcie >>>\na=2\n# <<< orchestrator:pcie <<<\n"
	if _, err := patchManagedBlock([]byte(dup), "x", "pcie"); err == nil {
		t.Fatal("expected error on duplicated marker pairs")
	}
}

// Content carrying its own marker lines must be refused at WRITE time.
//
// Writing it produces a duplicated pair, and the duplicate check then refuses
// every later apply of that marker — including the `stock` overclock revert,
// which is the one an operator reaches for when a node will not boot. The node
// is left with whatever config.txt it has and nothing in the product can change
// it.
func TestContentCarryingItsOwnMarkersIsRefused(t *testing.T) {
	original := []byte("dtparam=audio=on\n")

	for _, content := range []string{
		"# >>> orchestrator:overclock >>>\narm_freq=2000\n# <<< orchestrator:overclock <<<",
		"arm_freq=2000\n# >>> orchestrator:profile >>>",
		"  # <<< orchestrator:overclock <<<  ",
	} {
		if _, err := patchManagedBlock(original, content, "overclock"); err == nil {
			t.Errorf("content with an embedded marker was accepted:\n%s", content)
		}
	}
}

// Ordinary content that merely mentions the word must still work — the guard is
// about delimiter LINES, not about the string appearing anywhere.
func TestOrdinaryContentIsStillAccepted(t *testing.T) {
	original := []byte("dtparam=audio=on\n")
	content := "# orchestrator manages the block below\narm_freq=2000\n# see docs for orchestrator:overclock"

	out, err := patchManagedBlock(original, content, "overclock")
	if err != nil {
		t.Fatalf("ordinary content was refused: %v", err)
	}
	if !strings.Contains(string(out), "arm_freq=2000") {
		t.Fatalf("the content did not land:\n%s", out)
	}
}
