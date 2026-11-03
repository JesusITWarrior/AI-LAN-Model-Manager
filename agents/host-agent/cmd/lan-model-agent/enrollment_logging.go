package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/privatefile"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

// SCM does not collect stderr by default. Keep the latest redacted enrollment
// outcome in the already-protected state tree as well as structured telemetry.
// This file is diagnostic only and never authorizes or resumes enrollment.
func enrollmentLogger(stateDir string) service.OutputLogger {
	return func(entry service.LogEntry) {
		attrs := make([]any, 0, len(entry.Fields)*2)
		for key, value := range entry.Fields {
			attrs = append(attrs, key, value)
		}
		if entry.Level == "warn" {
			slog.Warn(entry.Message, attrs...)
		} else {
			slog.Info(entry.Message, attrs...)
		}
		if entry.Message != "host service enrollment complete" && entry.Message != "host service enrollment failed; local observation only" {
			return
		}
		if saveEnrollmentDiagnostic(stateDir, entry) != nil {
			slog.Warn("host service enrollment diagnostic unavailable")
		}
	}
}

func saveEnrollmentDiagnostic(stateDir string, entry service.LogEntry) error {
	if privatefile.Directory(stateDir) != nil {
		return privatefile.ErrPermissions
	}
	status := "degraded"
	if entry.Fields["status"] == enrollment.StatusEnrolled {
		status = enrollment.StatusEnrolled
	}
	record := map[string]any{"status": status, "observedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	if status != enrollment.StatusEnrolled {
		stage, _ := entry.Fields["stage"].(string)
		reason, _ := entry.Fields["reason"].(string)
		httpStatus, _ := entry.Fields["httpStatus"].(int)
		stage, reason, httpStatus = enrollment.FailureDetails(&enrollment.Failure{Stage: stage, Reason: reason, HTTPStatus: httpStatus})
		record["stage"], record["reason"] = stage, reason
		if httpStatus != 0 {
			record["httpStatus"] = httpStatus
		}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("enrollment diagnostic failed")
	}
	return saveDiagnostic(stateDir, "enrollment-status.json", raw)
}

// saveDiagnostic replaces one bounded, allowlisted status record in the protected
// state tree. Callers supply only locally constructed JSON, never provider data.
func saveDiagnostic(stateDir, filename string, raw []byte) error {
	if privatefile.Directory(stateDir) != nil {
		return privatefile.ErrPermissions
	}
	file, err := os.CreateTemp(stateDir, ".diagnostic-*")
	if err != nil {
		return fmt.Errorf("enrollment diagnostic failed")
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if file.Chmod(0600) != nil || privatefile.Check(file, 0600) != nil {
		return privatefile.ErrPermissions
	}
	if _, err = file.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("enrollment diagnostic failed")
	}
	if file.Sync() != nil || file.Close() != nil {
		return fmt.Errorf("enrollment diagnostic failed")
	}
	if os.Rename(name, filepath.Join(stateDir, filename)) != nil {
		return fmt.Errorf("enrollment diagnostic failed")
	}
	return nil
}
