package test

// Discriminating guard for Mythos #193858 / IAS-12602 (CWE-829).
//
// The release workflow builds and publishes the customer CLI binaries (which
// hold InsightAppSec + ThreadFix API keys on-host), so its supply-chain
// integrity matters. This test parses .github/workflows/release.yml and asserts
// the hardening invariants the fix established:
//
//   1. Every third-party action is pinned to a 40-hex commit SHA, never a
//      mutable tag/branch (@master, @v1, ...).
//   2. The goreleaser BINARY is pinned to an exact version (not a floating
//      "~> vN" range) so the built artifact is reproducible.
//   3. A least-privilege top-level `permissions:` block is present.
//   4. The checkout step sets fetch-depth: 0 so goreleaser has full tag history
//      for its changelog (checkout v4 defaults to a shallow depth-1 clone).
//
// It FAILS against the pre-fix workflow (goreleaser-action@master, floating @v1
// actions, no permissions block, no fetch-depth) and PASSES against the fix.
// It has ongoing value as a CI guard: it goes red if the workflow is ever
// un-pinned again.
//
// No network, no credentials, no running service required — unlike the
// integration test in this package.

import (
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
		vs := strings.TrimSpace(v.(string))
		if strings.ContainsAny(vs, "~^*") || strings.Contains(vs, "> v") || strings.Contains(vs, ">v") {
			t.Errorf("goreleaser binary version %q is a floating range, not an immutable pin (CWE-829); use an exact version like v0.184.0", vs)
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
		// yaml.v2 decodes an unquoted integer as int.
		if iv, isInt := fd.(int); !isInt || iv != 0 {
			t.Errorf("checkout fetch-depth is %v, want 0 (full history + tags for the changelog)", fd)
		}
	}
	if !found {
		t.Fatal("no actions/checkout step found in release workflow")
	}
}
