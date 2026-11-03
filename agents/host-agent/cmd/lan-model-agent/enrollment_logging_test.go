package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

func TestEnrollmentDiagnosticAllowlistAndAtomicReplacement(t *testing.T) {
	root := t.TempDir()
	entry := service.EnrollmentSummary(enrollment.Outcome{OperatorCode: "23456789"}, &enrollment.Failure{Stage: "complete", Reason: "rejected", HTTPStatus: 429})
	entry.Fields["operatorCode"] = "23456789"
	entry.Fields["proof"] = "never-copy-proof"
	if err := saveEnrollmentDiagnostic(root, entry); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "enrollment-status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "23456789") || strings.Contains(string(raw), "never-copy-proof") {
		t.Fatal("secret persisted in diagnostic")
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil || record["stage"] != "complete" || record["httpStatus"] != float64(429) {
		t.Fatal("failure status missing")
	}
	if err := saveEnrollmentDiagnostic(root, service.EnrollmentSummary(enrollment.Outcome{Status: enrollment.StatusEnrolled}, nil)); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(root, "enrollment-status.json"))
	if strings.Contains(string(raw), "429") || !strings.Contains(string(raw), "enrolled") {
		t.Fatal("stale failure retained")
	}
}
