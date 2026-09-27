package lmstudio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const officialNativeFixture = `{
  "models": [
    {
      "type": "llm",
      "publisher": "google",
      "key": "google/gemma-4-26b-a4b",
      "display_name": "Gemma 4 26B A4B",
      "architecture": "gemma4",
      "quantization": {"name": "Q4_K_M", "bits_per_weight": 4},
      "size_bytes": 17990911801,
      "params_string": "26B-A4B",
      "loaded_instances": [{
        "id": "google/gemma-4-26b-a4b",
        "config": {
          "context_length": 4096,
          "eval_batch_size": 512,
          "parallel": 4,
          "flash_attention": true,
          "num_experts": 8,
          "offload_kv_cache_to_gpu": true
        }
      }],
      "max_context_length": 262144,
      "format": "gguf",
      "capabilities": {
        "vision": true,
        "trained_for_tool_use": true,
        "reasoning": {"allowed_options": ["off", "on"], "default": "on"}
      },
      "description": null,
      "variants": ["google/gemma-4-26b-a4b@q4_k_m"],
      "selected_variant": "google/gemma-4-26b-a4b@q4_k_m"
    },
    {
      "type": "embedding",
      "publisher": "gaianet",
      "key": "text-embedding-nomic-embed-text-v1.5-embedding",
      "display_name": "Nomic Embed Text v1.5",
      "quantization": {"name": "F16", "bits_per_weight": 16},
      "size_bytes": 274290560,
      "params_string": null,
      "loaded_instances": [{"id":"embed-1","config":{"context_length":2048}}],
      "max_context_length": 2048,
      "format": "gguf"
    }
  ]
}`

func minimalNativeModel(key string) string {
	return fmt.Sprintf(`{"type":"llm","publisher":"test","key":%q,"display_name":%q,"quantization":null,"size_bytes":0,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":null}`, key, key)
}

func nativeList(models ...string) string {
	return `{"models":[` + strings.Join(models, ",") + `]}`
}

func TestListNativeModelsOfficialFixtureAndExactRequest(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader(officialNativeFixture)}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:1234/api/v1/models" || request.Body != nil {
			t.Fatalf("request = %s %s body=%v", request.Method, request.URL, request.Body)
		}
		if got := request.Header.Values("Accept"); !reflect.DeepEqual(got, []string{"application/json"}) {
			t.Fatalf("Accept = %#v", got)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("unexpected Authorization header")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))

	models, err := client.ListNativeModels(context.Background())
	if err != nil {
		t.Fatalf("ListNativeModels error = %v", err)
	}
	if len(models) != 2 || models[0].CanonicalName != "google/gemma-4-26b-a4b" || models[1].Type != provider.ModelTypeEmbedding {
		t.Fatalf("models = %#v", models)
	}
	model := models[0]
	if model.ModelID != "lmstudio-e2c66a64b20d05293f2db04c1cc9872667f5998e68a348f6020b9a5ac5891bd1" ||
		!model.ArchitectureKnown || model.Architecture != "gemma4" || !model.QuantizationKnown ||
		!model.QuantizationNameKnown || model.Quantization != "Q4_K_M" || !model.BitsPerWeightKnown || model.BitsPerWeight != 4 ||
		!model.CapabilitiesKnown || !model.Vision || !model.TrainedForToolUse || !model.ReasoningKnown ||
		!reflect.DeepEqual(model.ReasoningAllowedOptions, []string{"off", "on"}) || model.ReasoningDefault != "on" ||
		model.DescriptionKnown || !reflect.DeepEqual(model.Variants, []string{"google/gemma-4-26b-a4b@q4_k_m"}) {
		t.Fatalf("normalized LLM = %#v", model)
	}
	if !model.Loaded || len(model.LoadedInstances) != 1 {
		t.Fatalf("instances = %#v", model.LoadedInstances)
	}
	instance := model.LoadedInstances[0]
	if instance.InstanceID != "lmstudio-instance-554751b2c222e931c23992885b8694f74ae6a4dfed4e3e66280e1e743951d30e" ||
		instance.ProviderInstanceID != "google/gemma-4-26b-a4b" || instance.ModelID != model.ModelID ||
		instance.ContextLength != 4096 || !instance.EvaluationBatchSizeKnown || instance.EvaluationBatchSize != 512 ||
		!instance.ParallelKnown || instance.Parallel != 4 || !instance.FlashAttentionKnown || !instance.FlashAttention ||
		!instance.NumberOfExpertsKnown || instance.NumberOfExperts != 8 || !instance.OffloadKVCacheToGPUKnown || !instance.OffloadKVCacheToGPU ||
		instance.ObservedAt != "2026-09-27T03:01:02.987Z" {
		t.Fatalf("normalized instance = %#v", instance)
	}
	embedding := models[1]
	if !embedding.Loaded || embedding.ArchitectureKnown || embedding.CapabilitiesKnown || embedding.DescriptionKnown || embedding.ParameterSizeKnown ||
		embedding.ReasoningAllowedOptions == nil || embedding.Variants == nil || embedding.LoadedInstances == nil {
		t.Fatalf("embedding null/absent or slices = %#v", embedding)
	}
	wire, err := json.Marshal(models)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(wire), `"loaded":true`) != 2 || strings.Contains(string(wire), `"loaded":false`) {
		t.Fatalf("loaded JSON wire = %s", wire)
	}
	if !body.closed {
		t.Fatal("body not closed")
	}
}

func TestListNativeModelsSortsAndDoesNotAliasPriorResults(t *testing.T) {
	payload := nativeList(minimalNativeModel("z/model"), minimalNativeModel("A/model"))
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	}))
	first, err := client.ListNativeModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].CanonicalName != "A/model" || first[0].Loaded || first[0].Variants == nil || first[0].LoadedInstances == nil || first[0].ReasoningAllowedOptions == nil {
		t.Fatalf("first = %#v", first)
	}
	first[0].CanonicalName = "changed"
	first[0].Variants = append(first[0].Variants, "changed")
	first[0].LoadedInstances = append(first[0].LoadedInstances, provider.LoadedModelInstance{})
	wire, err := json.Marshal(first[1])
	if err != nil || !strings.Contains(string(wire), `"loaded":false`) {
		t.Fatalf("unloaded JSON wire = %s, %v", wire, err)
	}
	second, err := client.ListNativeModels(context.Background())
	if err != nil || second[0].CanonicalName != "A/model" || len(second[0].Variants) != 0 || len(second[0].LoadedInstances) != 0 {
		t.Fatalf("second = %#v, %v", second, err)
	}

	emptyClient := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"models":[]}`))}, nil
	}))
	empty, err := emptyClient.ListNativeModels(context.Background())
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty = %#v, %v", empty, err)
	}
}

func TestDecodeNativeModelsVariantPresenceAndMembership(t *testing.T) {
	base := minimalNativeModel("a")
	withSuffix := func(suffix string) string {
		return nativeList(strings.TrimSuffix(base, "}") + suffix + "}")
	}
	tests := []struct {
		name         string
		suffix       string
		wantVariants []string
		wantSelected string
		wantKnown    bool
		wantError    bool
	}{
		{name: "absent", wantVariants: []string{}},
		{name: "present empty", suffix: `,"variants":[]`, wantVariants: []string{}},
		{name: "present nonempty without selected", suffix: `,"variants":["a@q8","a@q4"]`, wantVariants: []string{"a@q4", "a@q8"}},
		{name: "selected member", suffix: `,"variants":["a@q8","a@q4"],"selected_variant":"a@q8"`, wantVariants: []string{"a@q4", "a@q8"}, wantSelected: "a@q8", wantKnown: true},
		{name: "selected without variants", suffix: `,"selected_variant":"a@q4"`, wantError: true},
		{name: "selected with empty variants", suffix: `,"variants":[],"selected_variant":"a@q4"`, wantError: true},
		{name: "selected absent member", suffix: `,"variants":["a@q4"],"selected_variant":"a@q8"`, wantError: true},
		{name: "selected empty", suffix: `,"variants":["a@q4"],"selected_variant":""`, wantError: true},
		{name: "duplicate variants", suffix: `,"variants":["a@q4","a@q4"]`, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			models, err := decodeNativeModels([]byte(withSuffix(test.suffix)), "p", "now")
			if test.wantError {
				if !errors.Is(err, ErrInvalidNativeModelsResponse) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			model := models[0]
			if model.Variants == nil || !reflect.DeepEqual(model.Variants, test.wantVariants) ||
				model.SelectedVariant != test.wantSelected || model.SelectedVariantKnown != test.wantKnown {
				t.Fatalf("model = %#v", model)
			}
		})
	}
}

func TestDecodeNativeModelsStrictContract(t *testing.T) {
	validWithNulls := `{"models":[{"type":"llm","publisher":"test","key":"a","display_name":"A","architecture":null,"quantization":{"name":null,"bits_per_weight":null},"size_bytes":0,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":null,"description":null}]}`
	if _, err := decodeNativeModels([]byte(validWithNulls), "p", "now"); err != nil {
		t.Fatalf("valid nullable contract rejected: %v", err)
	}

	base := minimalNativeModel("a")
	invalid := []string{
		"", "null", `[]`, `{}`, `{"models":null}`, `{"models":[],"extra":1}`,
		`{"models":[],"models":[]}`, `{"models":[]} {}`,
		nativeList(`{}`), nativeList(strings.Replace(base, `"type":"llm",`, "", 1)),
		nativeList(strings.Replace(base, `"publisher":"test",`, "", 1)),
		nativeList(strings.Replace(base, `"key":"a",`, "", 1)),
		nativeList(strings.Replace(base, `"display_name":"a",`, "", 1)),
		nativeList(strings.Replace(base, `"quantization":null,`, "", 1)),
		nativeList(strings.Replace(base, `"size_bytes":0,`, "", 1)),
		nativeList(strings.Replace(base, `"params_string":null,`, "", 1)),
		nativeList(strings.Replace(base, `"loaded_instances":[],`, "", 1)),
		nativeList(strings.Replace(base, `"max_context_length":1,`, "", 1)),
		nativeList(strings.Replace(base, `,"format":null`, "", 1)),
		nativeList(strings.Replace(base, `"type":"llm"`, `"type":"chat"`, 1)),
		nativeList(strings.Replace(base, `"key":"a"`, `"key":"../a"`, 1)),
		nativeList(strings.Replace(base, `"size_bytes":0`, `"size_bytes":-1`, 1)),
		nativeList(strings.Replace(base, `"max_context_length":1`, `"max_context_length":0`, 1)),
		nativeList(strings.Replace(base, `"format":null`, `"format":"safetensors"`, 1)),
		nativeList(strings.TrimSuffix(base, "}") + `,"extra":1}`),
		nativeList(strings.Replace(base, `"key":"a"`, `"key":"a","key":"a"`, 1)),
		nativeList(base, base),
		`{"models":[{"type":"embedding","publisher":"p","key":"e","display_name":"e","architecture":"bert","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":{"name":"Q4","name":"Q4","bits_per_weight":4},"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":{"name":"Q4"},"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf","selected_variant":"a@q4"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf","variants":["a@q4"],"selected_variant":"a@q8"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf","variants":["a@q4","a@q4"],"selected_variant":"a@q4"}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf","capabilities":{"vision":null,"trained_for_tool_use":false}}]}`,
		`{"models":[{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[],"max_context_length":1,"format":"gguf","capabilities":{"vision":false,"trained_for_tool_use":false,"reasoning":{"allowed_options":["on","on"],"default":"on"}}}]}`,
	}
	for _, body := range invalid {
		if _, err := decodeNativeModels([]byte(body), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
			t.Errorf("decodeNativeModels(%.180q) = %v", body, err)
		}
	}
	invalidUTF8 := append([]byte(`{"models":[]}`), 0xff)
	if _, err := decodeNativeModels(invalidUTF8, "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Errorf("invalid UTF-8 error = %v", err)
	}
	unpairedSurrogate := strings.Replace(base, `"display_name":"a"`, `"display_name":"\ud800"`, 1)
	if _, err := decodeNativeModels([]byte(nativeList(unpairedSurrogate)), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Errorf("unpaired surrogate error = %v", err)
	}
}

func TestDecodeNativeModelsInstanceRulesAndDuplicates(t *testing.T) {
	model := func(instances string) string {
		return `{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[` + instances + `],"max_context_length":1,"format":"gguf"}`
	}
	valid := nativeList(model(`{"id":"i","config":{"context_length":1,"eval_batch_size":1,"parallel":1,"flash_attention":false,"num_experts":1,"offload_kv_cache_to_gpu":false}}`))
	if _, err := decodeNativeModels([]byte(valid), "p", "now"); err != nil {
		t.Fatal(err)
	}
	invalidInstances := []string{
		`{}`, `{"id":"i"}`, `{"config":{"context_length":1}}`, `{"id":"i","config":null}`,
		`{"id":"i","config":{}}`, `{"id":"i","config":{"context_length":0}}`,
		`{"id":"i","config":{"context_length":1,"extra":1}}`,
		`{"id":"i","id":"j","config":{"context_length":1}}`,
		`{"id":"i","config":{"context_length":1,"flash_attention":null}}`,
	}
	for _, instance := range invalidInstances {
		if _, err := decodeNativeModels([]byte(nativeList(model(instance))), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
			t.Errorf("instance %s accepted: %v", instance, err)
		}
	}
	if _, err := decodeNativeModels([]byte(nativeList(model(`{"id":"i","config":{"context_length":1}},{"id":"i","config":{"context_length":1}}`))), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("duplicate instance error = %v", err)
	}

	other := strings.Replace(model(`{"id":"same","config":{"context_length":1}}`), `"key":"a"`, `"key":"b"`, 1)
	if _, err := decodeNativeModels([]byte(nativeList(model(`{"id":"same","config":{"context_length":1}}`), other)), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("global duplicate instance error = %v", err)
	}
}

func TestDecodeNativeModelsCanonicalKeyCasePolicy(t *testing.T) {
	models, err := decodeNativeModels([]byte(nativeList(
		minimalNativeModel("z/model"),
		minimalNativeModel("B/model"),
		minimalNativeModel("a/model"),
	)), "p", "now")
	if err != nil {
		t.Fatal(err)
	}
	gotNames := []string{models[0].CanonicalName, models[1].CanonicalName, models[2].CanonicalName}
	if !reflect.DeepEqual(gotNames, []string{"a/model", "B/model", "z/model"}) {
		t.Fatalf("ASCII case-insensitive order/source spelling = %#v", gotNames)
	}

	upper, err := decodeNativeModels([]byte(nativeList(minimalNativeModel("Owner/Model"))), "p", "now")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := decodeNativeModels([]byte(nativeList(minimalNativeModel("owner/model"))), "p", "later")
	if err != nil {
		t.Fatal(err)
	}
	if upper[0].CanonicalName != "Owner/Model" || lower[0].CanonicalName != "owner/model" || upper[0].ModelID != lower[0].ModelID {
		t.Fatalf("source keys or stable IDs = %#v %#v", upper[0], lower[0])
	}
	if _, err := decodeNativeModels([]byte(nativeList(minimalNativeModel("Owner/Model"), minimalNativeModel("owner/model"))), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("case-only duplicate error = %v", err)
	}
}

func TestDecodeNativeModelsStableProviderScopedIDsAndSorting(t *testing.T) {
	model := `{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[{"id":"z","config":{"context_length":1}},{"id":"A","config":{"context_length":1}}],"max_context_length":1,"format":"gguf","variants":["a@z","a@A"],"selected_variant":"a@z"}`
	first, err := decodeNativeModels([]byte(nativeList(model)), "provider-a", "now")
	if err != nil {
		t.Fatal(err)
	}
	again, err := decodeNativeModels([]byte(nativeList(model)), "provider-a", "later")
	if err != nil {
		t.Fatal(err)
	}
	other, err := decodeNativeModels([]byte(nativeList(model)), "provider-b", "now")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ModelID != again[0].ModelID || first[0].ModelID == other[0].ModelID ||
		first[0].LoadedInstances[0].InstanceID != again[0].LoadedInstances[0].InstanceID ||
		first[0].LoadedInstances[0].InstanceID == other[0].LoadedInstances[0].InstanceID {
		t.Fatalf("ids are not stable/provider-scoped: %#v %#v %#v", first, again, other)
	}
	if !reflect.DeepEqual(first[0].Variants, []string{"a@A", "a@z"}) || first[0].LoadedInstances[0].ProviderInstanceID != "A" || first[0].LoadedInstances[1].ProviderInstanceID != "z" {
		t.Fatalf("nested sorting = %#v", first[0])
	}
	first[0].Variants[0] = "mutated"
	first[0].LoadedInstances[0].ProviderInstanceID = "mutated"
	if again[0].Variants[0] != "a@A" || again[0].LoadedInstances[0].ProviderInstanceID != "A" {
		t.Fatalf("result slices alias across decodes: %#v", again[0])
	}
}

func TestDecodeNativeModelsLimits(t *testing.T) {
	buildModels := func(count int) []byte {
		models := make([]string, count)
		for index := range models {
			models[index] = minimalNativeModel(fmt.Sprintf("m%d", index))
		}
		return []byte(nativeList(models...))
	}
	if models, err := decodeNativeModels(buildModels(MaximumNativeModels), "p", "now"); err != nil || len(models) != MaximumNativeModels {
		t.Fatalf("model cap len=%d err=%v", len(models), err)
	}
	if _, err := decodeNativeModels(buildModels(MaximumNativeModels+1), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("model cap+1 error = %v", err)
	}

	instances := make([]string, MaximumLoadedInstances+1)
	for index := range instances {
		instances[index] = fmt.Sprintf(`{"id":"i%d","config":{"context_length":1}}`, index)
	}
	withInstances := func(count int) string {
		return `{"type":"llm","publisher":"p","key":"a","display_name":"a","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[` + strings.Join(instances[:count], ",") + `],"max_context_length":1,"format":null}`
	}
	if models, err := decodeNativeModels([]byte(nativeList(withInstances(MaximumLoadedInstances))), "p", "now"); err != nil || len(models[0].LoadedInstances) != MaximumLoadedInstances {
		t.Fatalf("instance cap err=%v", err)
	}
	if _, err := decodeNativeModels([]byte(nativeList(withInstances(MaximumLoadedInstances+1))), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("instance cap+1 error=%v", err)
	}

	variants := make([]string, MaximumModelVariants+1)
	for index := range variants {
		variants[index] = fmt.Sprintf(`"a@q%d"`, index)
	}
	withVariants := func(count int) string {
		return strings.TrimSuffix(minimalNativeModel("a"), "}") + `,"variants":[` + strings.Join(variants[:count], ",") + `],"selected_variant":"a@q0"}`
	}
	if _, err := decodeNativeModels([]byte(nativeList(withVariants(MaximumModelVariants))), "p", "now"); err != nil {
		t.Fatalf("variant cap error=%v", err)
	}
	if _, err := decodeNativeModels([]byte(nativeList(withVariants(MaximumModelVariants+1))), "p", "now"); !errors.Is(err, ErrInvalidNativeModelsResponse) {
		t.Fatalf("variant cap+1 error=%v", err)
	}
}

func TestListNativeModelsStableTransportErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   io.Reader
		want   error
	}{
		{"status", http.StatusUnauthorized, strings.NewReader("secret"), ErrNativeModelsHTTPStatus},
		{"malformed", http.StatusOK, strings.NewReader(`{"models":null}`), ErrInvalidNativeModelsResponse},
		{"oversize", http.StatusOK, strings.NewReader(strings.Repeat("x", MaximumNativeModelsBodySize+1)), ErrNativeModelsResponseTooLarge},
		{"read", http.StatusOK, readerFunc(func([]byte) (int, error) { return 0, errors.New("secret") }), ErrNativeModelsFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{Reader: test.body}
			client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: body}, nil
			}))
			if _, err := client.ListNativeModels(context.Background()); err != test.want || !body.closed {
				t.Fatalf("error=%v want=%v closed=%v", err, test.want, body.closed)
			}
		})
	}

	responseErrorBody := &trackedBody{Reader: strings.NewReader("secret")}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: responseErrorBody}, errors.New("transport secret")
	}))
	if _, err := client.ListNativeModels(context.Background()); err != ErrNativeModelsFailed || !responseErrorBody.closed {
		t.Fatalf("response+error=%v closed=%v", err, responseErrorBody.closed)
	}
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial secret")
	}))
	if _, err := client.ListNativeModels(context.Background()); err != ErrNativeModelsFailed {
		t.Fatalf("transport error=%v", err)
	}
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))
	if _, err := client.ListNativeModels(context.Background()); err != ErrNativeModelsFailed {
		t.Fatalf("nil response error=%v", err)
	}
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200}, nil }))
	if _, err := client.ListNativeModels(context.Background()); err != ErrNativeModelsFailed {
		t.Fatalf("nil body error=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil }))
	if _, err := client.ListNativeModels(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-cancel error=%v called=%v", err, called)
	}

	var deadlineBody *trackedBody
	deadlineClient, err := NewWithDependencies(Config{ProviderID: "p", Endpoint: "http://localhost", Timeout: MinimumTimeout}, doerFunc(func(request *http.Request) (*http.Response, error) {
		deadlineBody = &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
			<-request.Context().Done()
			return 0, errors.New("stopped")
		})}
		return &http.Response{StatusCode: 200, Body: deadlineBody}, nil
	}), fakeClock{time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deadlineClient.ListNativeModels(context.Background()); !errors.Is(err, context.DeadlineExceeded) || deadlineBody == nil || !deadlineBody.closed {
		t.Fatalf("deadline error=%v body=%#v", err, deadlineBody)
	}

	if ErrNativeModelsFailed == ErrListFailed || ErrNativeModelsHTTPStatus == ErrListHTTPStatus || ErrNativeModelsResponseTooLarge == ErrListResponseTooLarge || ErrInvalidNativeModelsResponse == ErrInvalidListResponse {
		t.Fatal("native sentinels must be distinct")
	}
}

func TestListNativeModelsProductionClientRejectsRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/models" {
			http.Redirect(writer, request, "/secret", http.StatusFound)
			return
		}
		redirected = true
		_, _ = io.WriteString(writer, `{"models":[]}`)
	}))
	defer server.Close()
	client, err := New(Config{ProviderID: "p", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListNativeModels(context.Background()); err != ErrNativeModelsHTTPStatus || redirected {
		t.Fatalf("error=%v redirected=%v", err, redirected)
	}
}
