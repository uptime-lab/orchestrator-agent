# Uptime Orchestrator — agent source mirror

This repository is a **read-only mirror** of the agent, the gRPC protocol and
the artifact signer of [Uptime Orchestrator](https://github.com/uptime-lab/orchestrator):
the directories `agent/`, `proto/` and `tools/agent-signer/`, pushed as one
commit per agent release. Everything here is under the
[Apache License 2.0](LICENSE); `NOTICE` is the attribution notice and
`THIRD-PARTY-NOTICES.md` reproduces the licence texts of the modules compiled
into the agent and watcher (the packages install the same three files under
`/usr/share/doc/<package>/`). `REUSE.toml` is the machine-readable form.

- **Releases**: each release is one commit, `agent <version> (mirror of
  <commit>)` naming the main repository's commit it was exported from, tagged
  `agent-v<version>`. Its GitHub Release carries
  `orchestrator-agent_<version>_linux_arm64.deb`,
  `orchestrator-watcher_<version>_linux_arm64.deb`, each one's detached
  signature `<file>.deb.sig`, and `orchestrator-agent-v<version>.spdx.json`,
  an SPDX SBOM of the `agent/` module. Check a package with
  `openssl dgst -sha384 -verify agent/pkg/signing/keys/agent-signing-<n>.pem -signature <file>.deb.sig <file>.deb`;
  devices verify the same signature against the same keys. No CI runs here
  and nothing in this repository builds a release: the maintainers build and
  sign the packages offline with a hardware-held key and attach them by hand.
  A Go-valid `agent/v<version>` tag is added only once the module path is
  canonical.
- **Building**: `cd agent && go build ./cmd/agent` works from a clone. The
  module path is not a canonical one yet, so `go get` does not resolve it.
- **Issues and pull requests**: this mirror accepts neither. Bugs and patches
  go to the main repository, `uptime-lab/orchestrator`.
- **Design documents** the code cites (`docs/NETWORK-FIRST.md`,
  `docs/UTILITIES-PLAN.md`, `docs/UTILITIES-RESEARCH.md`,
  `docs/HTTPBOOT-AUTH-RESEARCH.md`) live in the main repository.
- **Security reports**: use this repository's private vulnerability
  reporting, or `security@orchestrator.sh`; see `SECURITY.md`.
- **Trade marks**: "Uptime Orchestrator", the Uptime Lab name and the product
  logos are trade marks used by Uptime Lab Inc. (EU application pending); the
  Apache License grants no right to use them beyond identifying the origin of
  the software (section 6). A fork distributed to others must rename the
  product. Raspberry Pi is a trademark of Raspberry Pi Ltd, used here only to
  name the hardware the agent runs on.
