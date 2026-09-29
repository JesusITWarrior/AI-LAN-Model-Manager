package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

// Invoked only by the TypeScript mTLS integration test. It uses the real
// enrolled HTTPS client and the production verified installer.
func TestCrossLanguageArtifactInstallHelper(t *testing.T) {
	certDir, paramsPath, cacheDir, ollamaEndpoint, signerPath := os.Getenv("LANMM_CROSS_ARTIFACT_CERT_DIR"), os.Getenv("LANMM_CROSS_ARTIFACT_PARAMS"), os.Getenv("LANMM_CROSS_ARTIFACT_CACHE"), os.Getenv("LANMM_CROSS_ARTIFACT_OLLAMA"), os.Getenv("LANMM_CROSS_ARTIFACT_SIGNER")
	if certDir == "" || paramsPath == "" || cacheDir == "" || ollamaEndpoint == "" || signerPath == "" {
		t.Skip("cross-language artifact helper")
	}
	raw, err := os.ReadFile(paramsPath)
	if err != nil {
		t.Fatal(err)
	}
	params, err := command.ParseArtifactInstallParams(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPSClient(certDir)
	if err != nil {
		t.Fatal(err)
	}
	ollamaClient, err := ollama.New(ollama.Config{ProviderID: params.ProviderID, Endpoint: ollamaEndpoint, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	signerPEM, err := os.ReadFile(signerPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(signerPEM)
	if block == nil {
		t.Fatal("invalid signer key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsedKey.(*ecdsa.PublicKey)
	if err != nil || !ok {
		t.Fatal("invalid signer key")
	}
	verifier, err := command.NewECDSAManifestVerifier(params.Manifest.SignerID, key)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := command.NewVerifiedArtifactInstaller(cacheDir, client, verifier, command.OllamaVerifiedImporter{ProviderID: params.ProviderID, Client: ollamaClient}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := installer.Install(context.Background(), params)
	if os.Getenv("LANMM_CROSS_ARTIFACT_RESUME") == "1" {
		if err == nil {
			t.Fatal("expected first interrupted transfer")
		}
		result, err = installer.Install(context.Background(), params)
	}
	if os.Getenv("LANMM_CROSS_ARTIFACT_CORRUPT") == "1" {
		if !errors.Is(err, command.ErrArtifactDigestMismatch) {
			t.Fatalf("expected digest mismatch, got %v", err)
		}
		fmt.Println("LANMM_CROSS_ARTIFACT_CORRUPTION_REJECTED=true")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if fetch, replayErr := client.FetchArtifact(context.Background(), params.DownloadTicket, 0); replayErr == nil {
		fetch.Body.Close()
		t.Fatal("consumed ticket replay accepted")
	}
	bad := params.DownloadTicket[:63] + "0"
	if bad == params.DownloadTicket {
		bad = params.DownloadTicket[:63] + "1"
	}
	if fetch, unauthorizedErr := client.FetchArtifact(context.Background(), bad, 0); unauthorizedErr == nil {
		fetch.Body.Close()
		t.Fatal("unauthorized ticket accepted")
	}
	fmt.Printf("LANMM_CROSS_ARTIFACT_RESULT=installed:%t:bytes:%d:digest:%s\n", result.Installed, result.SizeBytes, result.Digest)
}
