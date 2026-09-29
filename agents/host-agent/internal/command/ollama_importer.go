package command

import (
	"context"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

// OllamaVerifiedImporter binds installation to exactly one configured Ollama
// provider. It exposes no arbitrary provider selection or provider endpoint.
type OllamaVerifiedImporter struct {
	ProviderID string
	Client     *ollama.Client
}

func (i OllamaVerifiedImporter) ImportVerified(ctx context.Context, providerID, model, format, path, digest string) error {
	if i.Client == nil || providerID != i.ProviderID || !provider.ValidateProviderID(i.ProviderID) {
		return NoProvider
	}
	return i.Client.ImportVerifiedArtifact(ctx, model, format, path, digest)
}
func (i OllamaVerifiedImporter) Inventory(ctx context.Context, providerID string) ([]provider.InstalledModel, error) {
	if i.Client == nil || providerID != i.ProviderID {
		return nil, NoProvider
	}
	return i.Client.ListInstalled(ctx)
}

var _ VerifiedArtifactImporter = OllamaVerifiedImporter{}
