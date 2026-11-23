package handlers

import (
	"path/filepath"
	"testing"
)

// Every file the access reconciler writes is refused to a tracked-file write
// or delete, under the names the reconciler actually uses: a write could grant
// NOPASSWD sudo where the entry asks for a password, and a delete could remove
// a grant or the login policy the platform believes is in place.
func TestTheAccessReconcilersFilesAreProtected(t *testing.T) {
	for _, rel := range []string{
		accessSudoersPrefix + "ops",
		accessDropInRel,
		accessTrustedCAsRel,
		filepath.Join(accessPrincipalsDirRel, "ops"),
		filepath.Join(accessCADirRel, "ca-1.pub"),
		filepath.Join(accessKeysDirRel, "ops"),
	} {
		path := "/" + rel
		if err := checkProtectedNames(path, ""); err == nil {
			t.Errorf("%s is written by the access reconciler and must be refused", path)
		}
	}
}

// The protection is not so wide that an operator's own drop-ins are refused.
func TestOperatorDropInsStayWritable(t *testing.T) {
	for _, path := range []string{
		"/etc/sudoers.d/ops",
		"/etc/sudoers.d/README",
		"/etc/ssh/sshd_config.d/50-local.conf",
		"/etc/ssh/ssh_config",
	} {
		if err := checkProtectedNames(path, ""); err != nil {
			t.Errorf("%s was refused: %v", path, err)
		}
	}
}
