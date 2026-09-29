package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

var ErrImportFailed = errors.New("ollama verified import failed")

// ImportVerifiedArtifact imports a local file only through Ollama's fixed blob
// and create APIs. The caller must have verified size, digest, and manifest
// binding before calling this method.
func (client *Client) ImportVerifiedArtifact(ctx context.Context, model, format, path, digest string) error {
	canonical, ok := provider.CanonicalOllamaModelName(model)
	if !ok || canonical != model || (format != "gguf" && format != "ollama") || !digestPattern.MatchString(digest) {
		return provider.ErrInvalidCommand
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrImportFailed
	}
	defer file.Close()
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint+"/api/blobs/sha256:"+digest, file)
	if err != nil {
		return ErrImportFailed
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.doer.Do(req)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrImportFailed
	}
	if response == nil || response.Body == nil || (response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK) {
		return ErrImportFailed
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, MaximumBodySize+1)); err != nil {
		return ErrImportFailed
	}
	payload, err := json.Marshal(struct {
		Model  string            `json:"model"`
		Files  map[string]string `json:"files"`
		Stream bool              `json:"stream"`
	}{Model: model, Files: map[string]string{"model.gguf": "sha256:" + digest}, Stream: false})
	if err != nil {
		return ErrImportFailed
	}
	req, err = http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint+"/api/create", bytes.NewReader(payload))
	if err != nil {
		return ErrImportFailed
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	response, err = client.doer.Do(req)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrImportFailed
	}
	if response == nil || response.Body == nil || response.StatusCode != http.StatusOK {
		return ErrImportFailed
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumBodySize+1))
	if err != nil || len(body) > MaximumBodySize {
		return ErrImportFailed
	}
	var result struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.Status != "success" {
		return ErrImportFailed
	}
	return nil
}
