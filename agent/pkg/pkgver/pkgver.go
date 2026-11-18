// Package pkgver extracts and compares agent package versions for the
// anti-rollback check: the artifact signature proves WHO built a
// package, not WHICH version the platform asked for — the version declared
// inside the signed bytes is the authoritative one.
package pkgver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Compare orders two version strings by their numeric dot-segments
// ("0.2.9" < "0.2.10"). A leading "v" and surrounding spaces are ignored; a
// pre-release suffix after "-" is ignored (a snapshot compares equal to its
// release). Missing segments count as zero. Non-numeric segments fall back to
// lexicographic comparison. Returns -1/0/1.
func Compare(a, b string) int {
	as := segments(a)
	bs := segments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		switch {
		case aerr == nil && berr == nil:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		default:
			if av != bv {
				if av < bv {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

// Equal reports whether two version strings denote the same release.
func Equal(a, b string) bool {
	return Compare(a, b) == 0
}

func segments(v string) []string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
}

const arMagic = "!<arch>\n"

// DebControlVersion returns the Version field declared in a .deb's control
// file. The .deb is an ar archive holding control.tar.gz (nfpm/GoReleaser
// output); an unreadable or unsupported package is an error — callers treat
// that as fail-closed.
func DebControlVersion(pkg []byte) (string, error) {
	if len(pkg) < len(arMagic) || string(pkg[:len(arMagic)]) != arMagic {
		return "", fmt.Errorf("not an ar archive (bad magic)")
	}
	rest := pkg[len(arMagic):]
	for len(rest) >= 60 {
		header := rest[:60]
		name := strings.TrimRight(string(header[0:16]), " ")
		name = strings.TrimSuffix(name, "/") // GNU ar stores "name/"
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil || size < 0 || 60+size > len(rest) {
			return "", fmt.Errorf("corrupt ar entry %q", name)
		}
		data := rest[60 : 60+size]

		if strings.HasPrefix(name, "control.tar") {
			switch {
			case name == "control.tar.gz":
				return controlVersionFromTarGz(data)
			case name == "control.tar":
				return controlVersionFromTar(bytes.NewReader(data))
			default:
				// xz/zst control archives are not produced by our release
				// pipeline; refusing beats silently skipping the check.
				return "", fmt.Errorf("unsupported control archive %q", name)
			}
		}

		// Entries are 2-byte aligned. The pad byte can push a final odd-sized
		// entry one byte past the buffer — clamp so a malformed (but validly
		// signed) package fails cleanly instead of panicking on the slice.
		advance := 60 + size
		if advance%2 == 1 {
			advance++
		}
		if advance >= len(rest) {
			break
		}
		rest = rest[advance:]
	}
	return "", fmt.Errorf("no control.tar entry found")
}

func controlVersionFromTarGz(data []byte) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("bad control.tar.gz: %w", err)
	}
	defer gz.Close()
	return controlVersionFromTar(gz)
}

func controlVersionFromTar(r io.Reader) (string, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("control file not found in control.tar")
		}
		if err != nil {
			return "", fmt.Errorf("bad control.tar: %w", err)
		}
		if strings.TrimPrefix(hdr.Name, "./") != "control" {
			continue
		}
		// The control file is small; cap the read defensively.
		content, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return "", fmt.Errorf("failed to read control file: %w", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if v, ok := strings.CutPrefix(line, "Version:"); ok {
				v = strings.TrimSpace(v)
				if v == "" {
					break
				}
				return v, nil
			}
		}
		return "", fmt.Errorf("control file has no Version field")
	}
}
