package test

// Guards the supply-chain hardening of .github/workflows/release.yml so a future
// edit can't silently un-pin it (Mythos #193858 / IAS-12602, CWE-829). Each test
// below states the one invariant it enforces; rationale is in PR #11.
//
// Note: nothing runs `go test` in CI yet, so this only fires locally until a
// push/pull_request test workflow is added.

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// Minimal shape of the bits of the workflow we assert on.
type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Steps []struct {
			Name string                 `yaml:"name"`
			Uses string                 `yaml:"uses"`
			With map[string]interface{} `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

var shaPin = regexp.MustCompile(`^[0-9a-f]{40}$`)

// An exact goreleaser version pin: v0.184.0 / 0.184.0. Anything else (latest,
// nightly, ~> v0, >= 1.0, 1.x, a bare int) is a floating/mutable ref and fails.
var exactVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

func loadReleaseWorkflow(t *testing.T) workflow {
	t.Helper()
	// test/ sits alongside .github/ at the repo root.
	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("could not parse %s: %v", path, err)
	}
	return wf
}

func releaseSteps(t *testing.T, wf workflow) []struct {
	Name string
	Uses string
	With map[string]interface{}
} {
	t.Helper()
	var out []struct {
		Name string
		Uses string
		With map[string]interface{}
	}
	for _, job := range wf.Jobs {
		for _, s := range job.Steps {
			out = append(out, struct {
				Name string
				Uses string
				With map[string]interface{}
			}{s.Name, s.Uses, s.With})
		}
	}
	if len(out) == 0 {
		t.Fatal("no steps found in release workflow")
	}
	return out
}

// (1) Every `uses:` is pinned to a 40-hex commit SHA — no @master / @vN tags.
func TestReleaseActionsArePinnedToCommitSha(t *testing.T) {
	for _, s := range releaseSteps(t, loadReleaseWorkflow(t)) {
		if s.Uses == "" {
			continue
		}
		at := strings.LastIndex(s.Uses, "@")
		if at < 0 {
			t.Errorf("step %q uses %q with no version ref", s.Name, s.Uses)
			continue
		}
		ref := s.Uses[at+1:]
		if !shaPin.MatchString(ref) {
			t.Errorf("step %q uses a mutable ref %q — must be pinned to a 40-hex commit SHA (CWE-829)", s.Name, s.Uses)
		}
	}
}

// (2) The goreleaser binary is pinned to an exact version, not a floating range.
func TestGoreleaserBinaryPinnedToExactVersion(t *testing.T) {
	var found bool
	for _, s := range releaseSteps(t, loadReleaseWorkflow(t)) {
		if !strings.Contains(s.Uses, "goreleaser/goreleaser-action@") {
			continue
		}
		found = true
		v, ok := s.With["version"]
		if !ok {
			t.Fatalf("goreleaser step has no `version` input — binary would default to ~> v2 and reject this repo's v0-era .goreleaser.yml")
		}
		vs, isStr := v.(string)
		if !isStr {
			t.Fatalf("goreleaser `version` is not a string (%T: %v) — expected an exact pin like v0.184.0", v, v)
		}
		vs = strings.TrimSpace(vs)
		// Positive allowlist: only an exact X.Y.Z pin passes. A denylist of range
		// operators would let latest/nightly/1.x slip through as "pinned".
		if !exactVersion.MatchString(vs) {
			t.Errorf("goreleaser binary version %q is not an immutable exact pin (CWE-829); use e.g. v0.184.0", vs)
		}
	}
	if !found {
		t.Fatal("no goreleaser-action step found in release workflow")
	}
}

// (3) A top-level least-privilege permissions block is present.
func TestReleaseHasLeastPrivilegePermissions(t *testing.T) {
	wf := loadReleaseWorkflow(t)
	if len(wf.Permissions) == 0 {
		t.Fatal("release workflow has no top-level `permissions:` block — GITHUB_TOKEN gets the broad default scope")
	}
	if wf.Permissions["contents"] != "write" {
		t.Errorf("expected permissions.contents=write (goreleaser creates the Release), got %q", wf.Permissions["contents"])
	}
	// Least-privilege = the required floor (contents:write) with no *dangerous*
	// over-grant. Reject the broad write scopes a release doesn't need, but allow
	// otherwise-benign additions (e.g. a future id-token:write for artifact
	// signing is itself least-privilege) rather than pinning an exact set.
	dangerous := map[string]bool{"actions": true, "packages": true, "administration": true, "security-events": true, "deployments": true}
	for scope, level := range wf.Permissions {
		if dangerous[scope] && level == "write" {
			t.Errorf("over-broad permission scope %q=%q — a release does not need it (least privilege)", scope, level)
		}
	}
}

// (4) checkout uses fetch-depth: 0 so goreleaser's changelog sees full tag history.
func TestCheckoutFetchesFullHistory(t *testing.T) {
	var found bool
	for _, s := range releaseSteps(t, loadReleaseWorkflow(t)) {
		if !strings.Contains(s.Uses, "actions/checkout@") {
			continue
		}
		found = true
		fd, ok := s.With["fetch-depth"]
		if !ok {
			t.Fatal("checkout step does not set fetch-depth: 0 — v4 defaults to a shallow depth-1 clone, breaking goreleaser's changelog")
		}
		// Actions inputs are strings, so unquoted 0 (yaml int) and quoted "0"
		// are equivalent — normalise before comparing.
		if fmt.Sprintf("%v", fd) != "0" {
			t.Errorf("checkout fetch-depth is %v, want 0 (full history + tags for the changelog)", fd)
		}
	}
	if !found {
		t.Fatal("no actions/checkout step found in release workflow")
	}
}
