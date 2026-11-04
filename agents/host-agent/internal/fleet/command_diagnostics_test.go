package fleet

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestCommandStageDiagnosticsAreFixedAndRedacted(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	secret := "Authorization: Bearer synthetic-secret /private/path model prompt signed-envelope"
	commandStage(secret, 9999)
	commandStage("POLL_SIGNATURE", 200)
	commandStage("RESULT_REJECTED", 400)
	text := output.String()
	if strings.Contains(text, secret) || strings.Contains(text, "synthetic-secret") || strings.Contains(text, "9999") {
		t.Fatal("untrusted diagnostic escaped")
	}
	for _, fixed := range []string{"UNKNOWN_STAGE", "POLL_SIGNATURE", "RESULT_REJECTED", `"httpStatus":0`, `"httpStatus":200`, `"httpStatus":400`} {
		if !strings.Contains(text, fixed) {
			t.Fatalf("missing fixed diagnostic %s", fixed)
		}
	}
}
