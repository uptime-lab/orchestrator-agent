package handlers

import (
	"strings"
	"testing"
)

const envBegin = "# >>> orchestrator:environment >>>"
const envEnd = "# <<< orchestrator:environment <<<"

func TestReconcileEnvironmentFreshFile(t *testing.T) {
	got, err := reconcileEnvironmentContent(nil, map[string]string{
		"B_TOKEN": "2",
		"A_TOKEN": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := envBegin + "\nA_TOKEN=1\nB_TOKEN=2\n" + envEnd + "\n"
	if string(got) != want {
		t.Fatalf("fresh file mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestReconcileEnvironmentPreservesForeignLines(t *testing.T) {
	original := "PATH=\"/usr/bin:/bin\"\n# operator note\nCUSTOM=keep\n"
	got, err := reconcileEnvironmentContent([]byte(original), map[string]string{"TOKEN": "x"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, keep := range []string{"PATH=\"/usr/bin:/bin\"", "# operator note", "CUSTOM=keep", "TOKEN=x"} {
		if !strings.Contains(s, keep) {
			t.Fatalf("expected %q to survive, got:\n%s", keep, s)
		}
	}
	if !strings.Contains(s, envBegin) || !strings.Contains(s, envEnd) {
		t.Fatalf("managed block markers missing:\n%s", s)
	}
}

// A file written by a pre-marker agent has the platform's keys merged straight
// into the body. The first marker-aware apply must move an incoming key INTO
// the block and leave no duplicate outside it.
func TestReconcileEnvironmentMigratesPreMarkerKeys(t *testing.T) {
	original := "PATH=/usr/bin\nTOKEN=old-value\n"
	got, err := reconcileEnvironmentContent([]byte(original), map[string]string{"TOKEN": "new-value"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, "TOKEN=old-value") {
		t.Fatalf("pre-marker copy was not migrated:\n%s", s)
	}
	if strings.Count(s, "TOKEN=") != 1 {
		t.Fatalf("expected exactly one TOKEN line:\n%s", s)
	}
	idx := strings.Index(s, "TOKEN=new-value")
	if idx == -1 || idx < strings.Index(s, envBegin) || idx > strings.Index(s, envEnd) {
		t.Fatalf("TOKEN did not land inside the managed block:\n%s", s)
	}
}

// The incoming set is the resolved effective set, so a key present in the block
// but absent from the set was DETACHED and must disappear — the defect this
// code exists to fix.
func TestReconcileEnvironmentPrunesDetachedKeys(t *testing.T) {
	original := "PATH=/usr/bin\n\n" + envBegin + "\nDETACHED=gone\nKEPT=old\n" + envEnd + "\n"
	got, err := reconcileEnvironmentContent([]byte(original), map[string]string{"KEPT": "new"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, "DETACHED") {
		t.Fatalf("detached key survived the reconcile:\n%s", s)
	}
	if !strings.Contains(s, "KEPT=new") || !strings.Contains(s, "PATH=/usr/bin") {
		t.Fatalf("expected content missing:\n%s", s)
	}
}

func TestReconcileEnvironmentEmptySetRemovesBlock(t *testing.T) {
	original := "PATH=/usr/bin\n\n" + envBegin + "\nLAST=secret\n" + envEnd + "\n"
	got, err := reconcileEnvironmentContent([]byte(original), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, "LAST") || strings.Contains(s, envBegin) || strings.Contains(s, envEnd) {
		t.Fatalf("empty set must remove the block and its markers:\n%s", s)
	}
	if !strings.Contains(s, "PATH=/usr/bin") {
		t.Fatalf("foreign line lost on block removal:\n%s", s)
	}
}

func TestReconcileEnvironmentEmptySetNoBlockIsUnchanged(t *testing.T) {
	original := "PATH=/usr/bin\nCUSTOM=keep\n"
	got, err := reconcileEnvironmentContent([]byte(original), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("file without a block must be untouched:\n got %q\nwant %q", got, original)
	}
}

func TestReconcileEnvironmentRefusesMalformedMarkers(t *testing.T) {
	cases := []string{
		envBegin + "\nA=1\n",    // begin without end
		"A=1\n" + envEnd + "\n", // end without begin
		envBegin + "\n" + envEnd + "\n" + envBegin + "\nX=1\n" + envEnd + "\n", // duplicated pair
	}
	for _, original := range cases {
		if _, err := reconcileEnvironmentContent([]byte(original), map[string]string{"A": "1"}); err == nil {
			t.Fatalf("expected refusal for malformed markers in %q", original)
		}
		if _, err := reconcileEnvironmentContent([]byte(original), nil); err == nil {
			t.Fatalf("expected removal refusal for malformed markers in %q", original)
		}
	}
}
