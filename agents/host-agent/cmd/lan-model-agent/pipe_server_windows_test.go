//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestWindowsConfiguredServiceExecutable(t *testing.T) {
	path := `C:\Program Files\LANModelManager\releases\agent\0.1.0-alpha.6\bin\lan-model-agent.exe`
	for _, accepted := range []string{path, `c:\PROGRAM FILES\LANModelManager\agent.EXE`, `D:\agent.exe`} {
		got, err := configuredServiceExecutable(`"` + accepted + `"`)
		if err != nil || got != accepted {
			t.Errorf("quoted local executable rejected: %q, %v", got, err)
		}
	}
	for name, command := range map[string]string{
		"installed-unquoted":   path,
		"unquoted-no-spaces":   `C:\agent.exe`,
		"empty":                `""`,
		"arguments":            `"` + path + `" --enrollment-code`,
		"quoted-arguments":     `"` + path + `" "--flag"`,
		"embedded-quote":       `"C:\Program" Files\agent.exe"`,
		"leading-space":        ` "` + path + `"`,
		"trailing-space":       `"` + path + `" `,
		"relative":             `"bin\agent.exe"`,
		"drive-relative":       `"C:agent.exe"`,
		"root-relative":        `"\agent.exe"`,
		"unc":                  `"\\server\share\agent.exe"`,
		"extended-device":      `"\\?\C:\agent.exe"`,
		"device":               `"\\.\C:\agent.exe"`,
		"alternate-stream":     `"C:\agent.exe:other.exe"`,
		"dot-segment":          `"C:\dir\.\agent.exe"`,
		"parent-segment":       `"C:\dir\..\agent.exe"`,
		"forward-slashes":      `"C:/dir/agent.exe"`,
		"non-executable":       `"C:\agent.cmd"`,
		"trailing-dot-alias":   `"C:\dir.\agent.exe"`,
		"trailing-space-alias": `"C:\dir \agent.exe"`,
		"control":              "\"C:\\bad\nname\\agent.exe\"",
		"nul":                  "\"C:\\bad\x00name\\agent.exe\"",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := configuredServiceExecutable(command); !errors.Is(err, errPipeServerPath) || got != "" {
				t.Fatalf("unsafe command accepted: %q, %v", got, err)
			}
		})
	}
}

// A harmless argv probe reproduces PowerShell 5.1's old sc.exe argument loss
// without invoking SCM, touching the registry, or requiring elevation.
func TestWindowsPowerShellLegacyServiceQuoteLoss(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := `C:\Program Files\LANModelManager\releases\agent\0.1.0-alpha.6\bin\lan-model-agent.exe`
	script := `$binary='` + path + `'; & '` + strings.ReplaceAll(executable, "'", "''") + `' '-test.run=^TestWindowsNativeArgvProbe$' ('"{0}"'-f$binary)`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LANMM_TEST_ARGV_PROBE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PowerShell argv fixture: %v %s", err, output)
	}
	var got string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &got); err != nil || got != path {
		t.Fatalf("legacy quote-loss fixture mismatch: %q, %v", output, err)
	}
}

func TestWindowsNativeArgvProbe(t *testing.T) {
	if os.Getenv("LANMM_TEST_ARGV_PROBE") != "1" {
		return
	}
	encoded, _ := json.Marshal(os.Args[len(os.Args)-1])
	fmt.Println(string(encoded))
	os.Exit(0)
}
