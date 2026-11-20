package handlers

import (
	"strings"
	"testing"
)

type layoutStep struct {
	path string
	kind archiveKind
	link string // hardlink source, when set
}

func judgeLayout(steps []layoutStep) error {
	m := archiveLayout{}
	for _, s := range steps {
		comps := strings.Split(s.path, "/")
		kind := s.kind
		if s.link != "" {
			src := strings.Split(s.link, "/")
			if err := m.parents(src, false); err != nil {
				return err
			}
			kind = m.kindOf(src)
		}
		if err := m.place(comps, kind); err != nil {
			return err
		}
	}
	return nil
}

// Whatever the anchored unpack would refuse because of an earlier member of
// the same archive is refused by the model, and nothing else is.
func TestArchiveLayoutRefusesWhatTheUnpackWould(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []layoutStep
		ok    bool
	}{
		{"plain tree", []layoutStep{{"sub", archiveDir, ""}, {"sub/a", archiveFile, ""}, {"deep/x/y", archiveFile, ""}}, true},
		{"symlink then nothing through it", []layoutStep{{"sub/a", archiveFile, ""}, {"d", archiveSymlink, ""}}, true},
		{"file replaces own symlink", []layoutStep{{"d", archiveSymlink, ""}, {"d", archiveFile, ""}}, true},
		{"hardlink to a member", []layoutStep{{"a", archiveFile, ""}, {"b", 0, "a"}}, true},
		{"member through own symlink", []layoutStep{{"sub", archiveDir, ""}, {"sub/a", archiveFile, ""}, {"d", archiveSymlink, ""}, {"d/x", archiveFile, ""}}, false},
		{"directory member through own symlink", []layoutStep{{"d", archiveSymlink, ""}, {"d/e", archiveDir, ""}}, false},
		{"directory member at own symlink", []layoutStep{{"d", archiveSymlink, ""}, {"d", archiveDir, ""}}, false},
		{"member below own file", []layoutStep{{"f", archiveFile, ""}, {"f/x", archiveFile, ""}}, false},
		{"file over own directory", []layoutStep{{"sub/a", archiveFile, ""}, {"sub", archiveFile, ""}}, false},
		{"symlink over own directory", []layoutStep{{"sub", archiveDir, ""}, {"sub", archiveSymlink, ""}}, false},
		{"hardlink source through own symlink", []layoutStep{{"sub/a", archiveFile, ""}, {"d", archiveSymlink, ""}, {"b", 0, "d/a"}}, false},
		{"hardlink to own symlink is a symlink", []layoutStep{{"l", archiveSymlink, ""}, {"h", 0, "l"}, {"h/x", archiveFile, ""}}, false},
	} {
		err := judgeLayout(tc.steps)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
