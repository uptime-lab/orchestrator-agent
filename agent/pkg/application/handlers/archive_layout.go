package handlers

import (
	"fmt"
	"strings"
)

// archiveLayout models the paths an archive itself creates, relative to the
// extraction root, so that the judging pass refuses what the anchored apply
// pass would refuse because of an EARLIER member of the same archive — before
// anything is written. Without it an archive could pass judgement and then
// stop part-way through the unpack: `d -> sub` followed by `d/x` is refused
// only once the symlink exists on disk, by which time the members before it
// are written.
//
// The apply pass never follows a symlink and never replaces a directory with
// another kind, so the rules are:
//   - every parent of a member must be a directory (an archive-created symlink
//     or file there is refused; a parent the archive has not named is created
//     as a directory, or is the destination's own and judged by the walk);
//   - a directory member cannot land where the archive made a non-directory,
//     and a non-directory member cannot land where it made a directory.
//
// Paths the destination already holds are not modelled: those refusals depend
// on the destination's own state and can still stop the unpack part-way.
type archiveLayout map[string]archiveKind

type archiveKind byte

const (
	archiveDir archiveKind = iota + 1
	archiveFile
	archiveSymlink
)

func (k archiveKind) String() string {
	switch k {
	case archiveDir:
		return "a directory"
	case archiveSymlink:
		return "a symlink"
	default:
		return "a file"
	}
}

// parents checks that every proper prefix of comps is, as far as the archive
// says, a directory, and records the ones it has not named as directories
// (the apply walk creates them). record is false for a lookup that creates
// nothing (a hardlink's source).
func (m archiveLayout) parents(comps []string, record bool) error {
	for i := 1; i < len(comps); i++ {
		p := strings.Join(comps[:i], "/")
		kind, known := m[p]
		if !known {
			if record {
				m[p] = archiveDir
			}
			continue
		}
		if kind != archiveDir {
			return fmt.Errorf("%s is %s created by this archive; refusing to extract through it", p, kind)
		}
	}
	return nil
}

// place records a member of the given kind at comps after checking it against
// what the archive already created there.
func (m archiveLayout) place(comps []string, kind archiveKind) error {
	if len(comps) == 0 {
		return nil
	}
	if err := m.parents(comps, true); err != nil {
		return err
	}
	p := strings.Join(comps, "/")
	if prev, known := m[p]; known && (prev == archiveDir) != (kind == archiveDir) {
		return fmt.Errorf("%s is %s created by this archive and cannot be replaced by %s", p, prev, kind)
	}
	m[p] = kind
	return nil
}

// kindOf is what a hardlink to comps creates: a link to a symlink is a symlink
// (linkat without AT_SYMLINK_FOLLOW), anything else a file.
func (m archiveLayout) kindOf(comps []string) archiveKind {
	if m[strings.Join(comps, "/")] == archiveSymlink {
		return archiveSymlink
	}
	return archiveFile
}
