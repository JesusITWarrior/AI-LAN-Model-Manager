package command

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

// Invoked by the real TS owner HTTP test with captured prepared-command params.
func TestOwnerPreparedLoadContractHelper(t *testing.T) {
	path := os.Getenv("LANMM_OWNER_LOAD_PARAMS")
	if path == "" {
		t.Skip("cross-language owner helper")
	}
	params, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(func() time.Time { return nowConstant })
	calls := 0
	switch os.Getenv("LANMM_OWNER_LOAD_KIND") {
	case "ollama":
		registry.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				if calls == 0 {
					return ok200(psEmpty()), nil
				}
				return ok200(psLoaded()), nil
			}
			var body struct {
				KeepAlive string `json:"keep_alive"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.KeepAlive != "300s" {
				t.Fatal("prepared retention did not reach provider")
			}
			calls++
			return ok200(successBody()), nil
		})))
	case "lmstudio":
		registry.RegisterLMStudio("lmstudio-main", newLMStudioClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatal("loaded LM Studio no-op mutated")
			}
			calls++
			return lmNativeState("instance-1"), nil
		})))
	default:
		t.Fatal("unsupported test kind")
	}
	result, err := registry.Execute(context.Background(), "load", params)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := result.(provider.LifecycleResult)
	if !ok || loaded.RuntimeState != provider.RuntimeLoaded || calls == 0 {
		t.Fatal("load not verified")
	}
	fmt.Println("OWNER_LOAD_CONTRACT=verified")
}
