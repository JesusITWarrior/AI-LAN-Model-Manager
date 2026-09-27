package ollama

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

// runningModelJSON builds one running-model object with explicit size and
// size_vram so residency classification can be exercised independently.
func runningModelJSON(size, sizeVRAM uint64) string {
	return `{"name":"qwen:latest","model":"qwen:latest","size":` + formatUint(size) +
		`,"digest":"` + digestA + `","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2","bert"],"parameter_size":"7.6B","quantization_level":"Q4_K_M"},` +
		`"expires_at":"2026-09-27T03:01:02.123456Z","size_vram":` + formatUint(sizeVRAM) +
		`,"context_length":8192}`
}

func listRunningOne(t *testing.T, size, sizeVRAM uint64) ([]provider.RunningModel, error) {
	t.Helper()
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"models":[` + runningModelJSON(size, sizeVRAM) + `]}`))}, nil
	}))
	return client.ListRunning(context.Background())
}

func TestListRunningResidencyClassification(t *testing.T) {
	cases := []struct {
		name string
		size uint64
		vram uint64
		want provider.Residency
	}{
		{"cpu-only-no-vram", 1024, 0, provider.ResidencyCPU},
		{"full-gpu-equal", 1024, 1024, provider.ResidencyGPU},
		{"full-gpu-vram-eq-size", 1, 1, provider.ResidencyGPU},
		{"split-portion-on-device", 1024, 400, provider.ResidencySplit},
		{"split-one-byte-behind", 1024, 1023, provider.ResidencySplit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			models, err := listRunningOne(t, tc.size, tc.vram)
			if err != nil {
				t.Fatalf("ListRunning error = %v", err)
			}
			if len(models) != 1 {
				t.Fatalf("models = %d, want 1", len(models))
			}
			if models[0].Residency != tc.want {
				t.Fatalf("Residency = %q, want %q", models[0].Residency, tc.want)
			}
			if models[0].SizeBytes != tc.size || models[0].SizeVRAMBytes != tc.vram {
				t.Fatalf("sizes not propagated: size=%d vram=%d", models[0].SizeBytes, models[0].SizeVRAMBytes)
			}
			if models[0].Modalities == nil {
				t.Fatal("Modalities is nil; must be a nonnil empty slice")
			}
			if len(models[0].Modalities) != 0 {
				t.Fatalf("Modalities = %q, want empty", models[0].Modalities)
			}
			if len(models[0].Families) != 2 {
				t.Fatalf("Families not carried: %v", models[0].Families)
			}
		})
	}
}

func TestListRunningSizeVRAMGreaterThanSizeIsInconsistent(t *testing.T) {
	if _, err := listRunningOne(t, 100, 200); err != ErrInvalidRunningResponse {
		t.Fatalf("size_vram(200)>size(100) error = %v, want ErrInvalidRunningResponse", err)
	}
	if _, err := listRunningOne(t, 1, 2); err != ErrInvalidRunningResponse {
		t.Fatalf("size_vram(2)>size(1) error = %v, want ErrInvalidRunningResponse", err)
	}
}

func TestListRunningModalitiesNonNilAndMutationIsolated(t *testing.T) {
	payload := `{"models":[` + runningModelJSON(1024, 400) + `]}`
	body := &trackedBody{Reader: strings.NewReader(payload)}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))
	models, err := client.ListRunning(context.Background())
	if err != nil || len(models) != 1 {
		t.Fatalf("ListRunning = %v, %v", models, err)
	}
	if models[0].Modalities == nil {
		t.Fatal("Modalities is nil; must never be nil")
	}
	if len(models[0].Modalities) != 0 {
		t.Fatalf("Modalities = %q, want empty", models[0].Modalities)
	}

	// Mutate the prior result's modalities, then re-run; the result must not
	// alias the caller's slice.
	models[0].Modalities = []string{"vision"}
	models[0].Families = append(models[0].Families, "injected")
	body.closed = false
	body.Reader = strings.NewReader(payload)
	again, err := client.ListRunning(context.Background())
	if err != nil || len(again) != 1 {
		t.Fatalf("re-run = %v, %v", again, err)
	}
	if again[0].Modalities == nil || len(again[0].Modalities) != 0 {
		t.Fatalf("modalities leaked from prior mutation: %v", again[0].Modalities)
	}
	if len(again[0].Families) != 2 || again[0].Families[0] != "qwen2" || again[0].Families[1] != "bert" {
		t.Fatalf("families leaked from prior mutation: %v", again[0].Families)
	}
}

func TestListRunningDuplicateCanonicalNameRejected(t *testing.T) {
	// Two fully valid, differently-cased names that normalize to the same
	// canonical name, each with a distinct valid digest: both collapse to a
	// single canonical name, so the canonical-name dedupe is the real rejection
	// criterion (the SHA-256 runtime identity cannot be meaningfully tested at
	// unit scale). The rejection must reach the canonical-name branch.
	payload := `{"models":[` + runningModelCustom("Qwen:Latest", 100, 40, digestA) + `,` + runningModelCustom("qwen:latest", 100, 40, digestB) + `]}`
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	}))
	if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
		t.Fatalf("duplicate canonical error = %v, want ErrInvalidRunningResponse", err)
	}
}

func TestListRunningTransportErrorClosesBodyAndReturnsFailed(t *testing.T) {
	// A nonnil response carrying a tracked body, combined with a transport error
	// from the doer, must close that body and return the stable, redacted
	// ErrRunningFailed sentinel (with no secret or endpoint detail leaked).
	body := &trackedBody{Reader: strings.NewReader("super-secret-list")}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, errors.New("dial secret.internal token=secret")
	}))
	_, err := client.ListRunning(context.Background())
	if err != ErrRunningFailed || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "11434") {
		t.Fatalf("error = %v, want stable redacted ErrRunningFailed", err)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
}

func TestListRunningSizesOverflowAndNonIntegerRejected(t *testing.T) {
	t.Run("size overflow", func(t *testing.T) {
		payload := `{"models":[` + runningModelJSON(0, 0) + `,"size":18446744073709551616]}`
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
		}))
		if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
			t.Fatalf("size 2^64 error = %v, want ErrInvalidRunningResponse", err)
		}
	})
	t.Run("size_vram overflow", func(t *testing.T) {
		payload := `{"models":[` + runningModelJSON(0, 0) + `,"size_vram":18446744073709551616]}`
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
		}))
		if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
			t.Fatalf("size_vram 2^64 error = %v, want ErrInvalidRunningResponse", err)
		}
	})
	t.Run("size noninteger", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"models":[` + runningModelJSON(0, 0) + `,"size":1.5]}`))}, nil
		}))
		if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
			t.Fatalf("noninteger size error = %v, want ErrInvalidRunningResponse", err)
		}
	})
	t.Run("size_vram noninteger", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"models":[` + runningModelJSON(0, 0) + `,"size_vram":2.5]}`))}, nil
		}))
		if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
			t.Fatalf("noninteger size_vram error = %v, want ErrInvalidRunningResponse", err)
		}
	})
}

func TestListRunningPreCancelledContextFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport should not be used after pre-cancel")
		return nil, nil
	}))
	if _, err := client.ListRunning(ctx); !isCanceled(err) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestListRunningNilBodyReturnsFailed(t *testing.T) {
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: nil}, nil
	}))
	if _, err := client.ListRunning(context.Background()); err != ErrRunningFailed {
		t.Fatalf("nil body error = %v, want ErrRunningFailed", err)
	}
}

func TestListRunningRedactedErrorResponse(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("super-secret-model-list")}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: body}, nil
	}))
	_, err := client.ListRunning(context.Background())
	if err != ErrRunningHTTPStatus {
		t.Fatalf("error = %v, want ErrRunningHTTPStatus", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "127.0.0.1:11434") {
		t.Fatalf("error leaked sensitive detail: %q", err.Error())
	}
	if !body.closed {
		t.Fatal("response body not closed")
	}
}

func isCanceled(err error) bool {
	return err == context.Canceled
}
