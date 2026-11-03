package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

// One reporter is owned by the sequential fleet collector across session
// generations. Emit only transitions; replace one small latest-outcome file so
// SCM operators have diagnostics even when stderr is not captured. Never log
// endpoints, response bodies, names, arbitrary errors, or inventory metadata.
type inventoryReporter struct {
	stateDir            string
	lastProbe, lastList string
	initialized         bool
}

func inventoryReason(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ollama.ErrHTTPStatus), errors.Is(err, ollama.ErrListHTTPStatus):
		return "http_status"
	case errors.Is(err, ollama.ErrListResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, ollama.ErrInvalidResponse), errors.Is(err, ollama.ErrInvalidListResponse):
		return "invalid_response"
	default:
		return "request_failed"
	}
}

func (r *inventoryReporter) record(probeErr, listErr error) {
	probe, list := inventoryReason(probeErr), inventoryReason(listErr)
	if r.initialized && r.lastProbe == probe && r.lastList == list {
		return
	}
	r.initialized, r.lastProbe, r.lastList = true, probe, list
	status := "ready"
	if probe != "ok" || list != "ok" {
		status = "degraded"
	}
	raw, _ := json.Marshal(map[string]string{"status": status, "probe": probe, "list": list, "observedAt": time.Now().UTC().Format(time.RFC3339Nano)})
	if saveDiagnostic(r.stateDir, "inventory-status.json", raw) != nil {
		// Retry persistence next observation, without including filesystem details.
		r.initialized = false
		slog.Warn("host service inventory diagnostic unavailable")
	}
	if status == "ready" {
		slog.Info("host service inventory ready", "probe", probe, "list", list)
	} else {
		slog.Warn("host service inventory degraded", "probe", probe, "list", list)
	}
}
