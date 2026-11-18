package handlers

import (
	"fmt"

	"agent/pkg/pkgver"
)

// checkUpdatePolicy is the anti-rollback gate for agent package installs.
// The signature proves who built the package, not which version
// the platform asked for — so the version DECLARED inside the signed bytes is
// authoritative:
//
//   - declared must match the requested version when a concrete one was
//     requested (a CDN serving a different — e.g. older signed — artifact under
//     a newer name is refused);
//   - the effective version must not be older than the running agent unless
//     the operator explicitly allowed a downgrade.
//
// declared may be empty when the package format has no parsed version (rpm);
// then the requested version is the best available floor, and "latest" cannot
// be floor-checked at all (legacy behavior, deb fleets are unaffected).
func checkUpdatePolicy(running, requested, declared string, allowDowngrade bool) error {
	target := declared
	if target == "" {
		if requested == "" || requested == "latest" {
			return nil
		}
		target = requested
	} else if requested != "" && requested != "latest" && !pkgver.Equal(declared, requested) {
		return fmt.Errorf("package declares version %s but %s was requested — refusing (the CDN served a different artifact)", declared, requested)
	}

	// Dev builds carry the ldflags default and enforce no floor.
	if running == "" || running == "0.0.0" || allowDowngrade {
		return nil
	}
	if pkgver.Compare(target, running) < 0 {
		return fmt.Errorf("package version %s is older than the running agent %s — refusing rollback (set allow_downgrade to override)", target, running)
	}
	return nil
}
