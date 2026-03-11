//go:build windows
// +build windows

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetTargetPath_UsesStartupFolderAndRandomizedOvdName(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)

	got, err := getTargetPath()
	if err != nil {
		t.Fatalf("getTargetPath failed: %v", err)
	}

	wantDir := filepath.Join(appData, startupFolderRelative)
	if !strings.EqualFold(filepath.Clean(filepath.Dir(got)), filepath.Clean(wantDir)) {
		t.Fatalf("expected dir %q, got %q", wantDir, filepath.Dir(got))
	}
	base := strings.ToLower(filepath.Base(got))
	if !strings.HasPrefix(base, startupExecutablePrefix) || !strings.HasSuffix(base, ".exe") {
		t.Fatalf("expected randomized ovd_*.exe name, got %q", filepath.Base(got))
	}
}

func TestGetTargetPath_PrefersExistingPrefixedExecutable(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)
	startupDir := filepath.Join(appData, startupFolderRelative)
	if err := os.MkdirAll(startupDir, 0755); err != nil {
		t.Fatalf("mkdir startup dir failed: %v", err)
	}

	expected := filepath.Join(startupDir, "ovd_existing.exe")
	if err := os.WriteFile(expected, []byte("x"), 0644); err != nil {
		t.Fatalf("write startup executable failed: %v", err)
	}

	got, err := getTargetPath()
	if err != nil {
		t.Fatalf("getTargetPath failed: %v", err)
	}

	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(expected)) {
		t.Fatalf("expected existing startup executable %q, got %q", expected, got)
	}
}

func TestIsOverlordRunValueName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "Legacy", in: "OverlordAgent", want: true},
		{name: "LegacyCaseInsensitive", in: "overlordagent", want: true},
		{name: "Randomized", in: "OverlordAgent-a1b2c3d4e5f6", want: true},
		{name: "RandomizedCaseInsensitive", in: "overlordagent-deadbeefcafe", want: true},
		{name: "OtherApp", in: "OneDrive", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOverlordRunValueName(tt.in); got != tt.want {
				t.Fatalf("isOverlordRunValueName(%q)=%v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
