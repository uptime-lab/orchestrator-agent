//go:build linux

package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderDockerDaemonJSONDefaults(t *testing.T) {
	out, err := mergeDockerDaemonJSON(nil, map[string]interface{}{
		"log_max_size": "10m",
		"log_max_file": float64(3),
		"live_restore": true,
	})
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("rendered daemon.json is not valid JSON: %v", err)
	}
	opts, _ := doc["log-opts"].(map[string]interface{})
	if opts["max-size"] != "10m" || opts["max-file"] != "3" {
		t.Fatalf("log caps not rendered: %v", doc)
	}
	if doc["live-restore"] != true {
		t.Fatalf("live-restore not rendered: %v", doc)
	}
}

func TestRenderDockerDaemonJSONRefusesUnsafeParams(t *testing.T) {
	if _, err := mergeDockerDaemonJSON(nil, map[string]interface{}{
		"registry_mirrors": "http://mirror.internal",
	}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatal("a plaintext mirror must be refused — it is a supply-chain downgrade")
	}
	if _, err := mergeDockerDaemonJSON(nil, map[string]interface{}{
		"data_root": "relative/path",
	}); err == nil {
		t.Fatal("a relative data_root must be refused")
	}
	if _, err := mergeDockerDaemonJSON(nil, map[string]interface{}{
		"data_root": "/mnt/../etc",
	}); err == nil {
		t.Fatal("a traversing data_root must be refused")
	}
}

func TestDockerLogParamsValidated(t *testing.T) {
	// Accepted shapes normalize to lowercase; dockerd starts with all of them.
	for _, ok := range []string{"10m", "512k", "1g", "100", "10M"} {
		out, err := mergeDockerDaemonJSON(nil, map[string]interface{}{"log_max_size": ok})
		if err != nil {
			t.Fatalf("log_max_size %q must be accepted: %v", ok, err)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("invalid JSON for %q: %v", ok, err)
		}
		opts, _ := doc["log-opts"].(map[string]interface{})
		if opts["max-size"] != strings.ToLower(ok) {
			t.Fatalf("log_max_size %q rendered as %v", ok, opts["max-size"])
		}
	}
	// A typo here does not fail the apply — it takes dockerd down on every
	// node of the assignment. Refuse it before it reaches daemon.json.
	for _, bad := range []string{"10mb", "0m", "-5m", "m10", "10 m", "ten", "10.5m"} {
		if _, err := mergeDockerDaemonJSON(nil, map[string]interface{}{"log_max_size": bad}); err == nil {
			t.Fatalf("log_max_size %q must be refused", bad)
		}
	}
	for _, bad := range []string{"abc", "0", "-1", "3m"} {
		if _, err := mergeDockerDaemonJSON(nil, map[string]interface{}{"log_max_file": bad}); err == nil {
			t.Fatalf("log_max_file %q must be refused", bad)
		}
	}
}

func TestMergeDockerDaemonJSONPreservesForeignKeys(t *testing.T) {
	existing := []byte(`{
  "data-root": "/mnt/ssd/docker",
  "insecure-registries": ["10.0.0.5:5000"],
  "default-address-pools": [{"base": "10.0.0.0/16", "size": 24}],
  "log-opts": {"max-size": "1g", "labels": "env"}
}`)
	out, err := mergeDockerDaemonJSON(existing, map[string]interface{}{
		"log_max_size": "10m",
	})
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("merged daemon.json is not valid JSON: %v", err)
	}
	// The operator's data-root survives — a wholesale replace would revert it
	// and orphan every existing container.
	if doc["data-root"] != "/mnt/ssd/docker" {
		t.Fatalf("operator data-root clobbered: %v", doc)
	}
	if _, ok := doc["insecure-registries"]; !ok {
		t.Fatalf("foreign key insecure-registries dropped: %v", doc)
	}
	if _, ok := doc["default-address-pools"]; !ok {
		t.Fatalf("foreign key default-address-pools dropped: %v", doc)
	}
	// Managed keys are set as a unit: log-opts is ours and is replaced whole.
	opts, _ := doc["log-opts"].(map[string]interface{})
	if opts["max-size"] != "10m" {
		t.Fatalf("managed log-opts not applied: %v", doc)
	}
	if doc["log-driver"] != "json-file" {
		t.Fatalf("log-driver not set: %v", doc)
	}
}

func TestMergeDockerDaemonJSONRefusesInvalidExisting(t *testing.T) {
	_, err := mergeDockerDaemonJSON([]byte("{not json"), map[string]interface{}{})
	if err == nil {
		t.Fatal("an invalid existing daemon.json must be refused, never clobbered")
	}
	if !strings.Contains(err.Error(), dockerDaemonJSONPath) {
		t.Fatalf("the refusal must name the file the operator has to fix: %v", err)
	}
	// Whitespace-only counts as absent, not as invalid JSON.
	if _, err := mergeDockerDaemonJSON([]byte("  \n"), map[string]interface{}{}); err != nil {
		t.Fatalf("a whitespace-only existing file must merge as empty: %v", err)
	}
}

func TestCreatedFileSetTracksOnlyThisRunsFiles(t *testing.T) {
	var s createdFileSet
	s.record("/etc/apt/sources.list.d/zerotier.list", false)
	s.record("/usr/share/keyrings/zerotier-releases.gpg", true) // pre-existed: never removable
	s.record("/etc/apt/sources.list.d/zerotier.list", false)    // duplicate record is one entry
	got := s.paths()
	if len(got) != 1 || got[0] != "/etc/apt/sources.list.d/zerotier.list" {
		t.Fatalf("cleanup set must hold exactly the files this run created: %v", got)
	}
	var empty createdFileSet
	if len(empty.paths()) != 0 {
		t.Fatalf("an untouched set must be empty: %v", empty.paths())
	}
}
