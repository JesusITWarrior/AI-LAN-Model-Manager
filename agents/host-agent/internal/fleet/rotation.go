package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	agentcert "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/certificate"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
)

const identityPointerName = "fleet-identity-current"

var generationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type pendingRotation struct {
	Generation        string `json:"generation"`
	KeyPEM            string `json:"keyPem"`
	CSRPEM            string `json:"csrPem"`
	SourceFingerprint string `json:"sourceFingerprint"`
}
type rotationResponse struct {
	OK     bool `json:"ok"`
	Result *struct {
		CertificatePEM string `json:"certificatePem"`
		CAPEM          string `json:"caPem"`
		Fingerprint    string `json:"fingerprint"`
		Serial         string `json:"serial"`
		NotBefore      string `json:"notBefore"`
		NotAfter       string `json:"notAfter"`
	} `json:"result"`
	Error *string `json:"error,omitempty"`
}

func loadFleetIdentity(certDir string) (enrollment.Result, *ecdsa.PrivateKey, error) {
	pointer := filepath.Join(certDir, identityPointerName)
	if raw, err := os.ReadFile(pointer); err == nil {
		var generation string
		if json.Unmarshal(raw, &generation) != nil || !generationPattern.MatchString(generation) {
			return enrollment.Result{}, nil, ErrHTTPClient
		}
		root := filepath.Join(certDir, "fleet-identities", generation)
		info, e := os.Lstat(root)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return enrollment.Result{}, nil, ErrHTTPClient
		}
		result, e := loadResultFile(filepath.Join(root, "enrollment.json"))
		if e != nil {
			return enrollment.Result{}, nil, ErrHTTPClient
		}
		key, e := loadPrivateKeyFile(filepath.Join(root, "host-key.pem"))
		return result, key, e
	} else if !errors.Is(err, os.ErrNotExist) {
		return enrollment.Result{}, nil, ErrHTTPClient
	}
	result, err := (enrollment.FileStore{CertDir: certDir}).Load(context.Background())
	if err != nil {
		return enrollment.Result{}, nil, ErrHTTPClient
	}
	key, err := (enrollment.IdentityStore{CertDir: certDir}).Load()
	if err != nil {
		return enrollment.Result{}, nil, ErrHTTPClient
	}
	return result, key, nil
}
func loadResultFile(path string) (enrollment.Result, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() < 2 || info.Size() > 1<<20 {
		return enrollment.Result{}, ErrHTTPClient
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return enrollment.Result{}, ErrHTTPClient
	}
	var result enrollment.Result
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(&struct{}{}) != io.EOF {
		return enrollment.Result{}, ErrHTTPClient
	}
	return result, nil
}
func loadPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 64<<10 {
		return nil, ErrHTTPClient
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrHTTPClient
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, ErrHTTPClient
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return nil, ErrHTTPClient
	}
	return key, nil
}

// RotateIdentityIfNeeded rotates an expiring host identity over the currently
// authenticated mTLS channel. A durable pending CSR makes controller-side
// revocation recoverable after interruption; the new key and public enrollment
// become active together through one fsynced pointer rename.
func RotateIdentityIfNeeded(ctx context.Context, certDir string, renewBefore time.Duration) (bool, error) {
	if ctx == nil || renewBefore < time.Hour || renewBefore > 90*24*time.Hour {
		return false, ErrHTTPClient
	}
	current, key, err := loadFleetIdentity(certDir)
	if err != nil {
		return false, ErrHTTPClient
	}
	if enrollment.VerifyIssued(current, key, current.CAPEM, current.PinnedCAFingerprintSHA256, time.Now()) != nil {
		return false, ErrHTTPClient
	}
	block, _ := pem.Decode([]byte(current.CertificatePEM))
	if block == nil {
		return false, ErrHTTPClient
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, ErrHTTPClient
	}
	if !certificateRenewalDue(leaf, time.Now(), renewBefore) {
		_ = os.Remove(filepath.Join(certDir, "rotation-pending.json"))
		return false, nil
	}
	digest := sha256.Sum256(leaf.Raw)
	source := hex.EncodeToString(digest[:])
	pending, err := loadOrCreatePending(certDir, current, source)
	if err != nil {
		return false, ErrHTTPClient
	}
	client, err := NewHTTPSClient(certDir)
	if err != nil {
		return false, ErrHTTPClient
	}
	defer client.CloseIdleConnections()
	body, _ := json.Marshal(map[string]string{"csrPem": pending.CSRPEM})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base+"/agent/v1/certificate/rotate", bytes.NewReader(body))
	if err != nil {
		return false, ErrHTTPClient
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	response, err := client.http.Do(req)
	if err != nil {
		return false, ErrHTTPClient
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK || len(raw) > 64<<10 {
		return false, ErrHTTPClient
	}
	var decoded rotationResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF || !decoded.OK || decoded.Result == nil {
		return false, ErrHTTPClient
	}
	if decoded.Result.CAPEM != current.CAPEM {
		return false, ErrHTTPClient
	}
	next := current
	next.CertificatePEM = decoded.Result.CertificatePEM
	next.CAPEM = decoded.Result.CAPEM
	next.EnrolledAt = time.Now().UTC()
	newKey, err := parsePendingKey(pending.KeyPEM)
	if err != nil || enrollment.VerifyIssued(next, newKey, next.CAPEM, current.PinnedCAFingerprintSHA256, time.Now()) != nil {
		return false, ErrHTTPClient
	}
	newBlock, _ := pem.Decode([]byte(next.CertificatePEM))
	if newBlock == nil {
		return false, ErrHTTPClient
	}
	newLeaf, err := x509.ParseCertificate(newBlock.Bytes)
	if err != nil {
		return false, ErrHTTPClient
	}
	newDigest := sha256.Sum256(newLeaf.Raw)
	if hex.EncodeToString(newDigest[:]) != decoded.Result.Fingerprint || strings.ToUpper(newLeaf.SerialNumber.Text(16)) != decoded.Result.Serial {
		return false, ErrHTTPClient
	}
	if err = publishIdentityGeneration(certDir, pending, next); err != nil {
		return false, ErrHTTPClient
	}
	_ = os.Remove(filepath.Join(certDir, "rotation-pending.json"))
	return true, nil
}
func certificateRenewalDue(leaf *x509.Certificate, now time.Time, renewBefore time.Duration) bool {
	return leaf != nil && !now.IsZero() && renewBefore > 0 && !leaf.NotAfter.After(now.Add(renewBefore))
}

func loadOrCreatePending(certDir string, current enrollment.Result, source string) (pendingRotation, error) {
	path := filepath.Join(certDir, "rotation-pending.json")
	if raw, err := os.ReadFile(path); err == nil {
		var value pendingRotation
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&value) != nil || d.Decode(&struct{}{}) != io.EOF || !generationPattern.MatchString(value.Generation) || value.SourceFingerprint != source {
			return pendingRotation{}, ErrHTTPClient
		}
		if _, err = parsePendingKey(value.KeyPEM); err != nil {
			return pendingRotation{}, ErrHTTPClient
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingRotation{}, ErrHTTPClient
	}
	request, err := agentcert.GenerateRequest(agentcert.Binding{CandidateID: current.Binding.CandidateID, Address: current.Binding.Address, Port: current.Binding.Port, ProtocolMajor: current.Binding.ProtocolMajor, ProtocolMinor: current.Binding.ProtocolMinor})
	if err != nil {
		return pendingRotation{}, ErrHTTPClient
	}
	generationBytes := sha256.Sum256(request.CSRPEM)
	value := pendingRotation{Generation: hex.EncodeToString(generationBytes[:16]), KeyPEM: string(request.PrivateKeyPEM), CSRPEM: string(request.CSRPEM), SourceFingerprint: source}
	if err = atomicJSON(path, value); err != nil {
		return pendingRotation{}, ErrHTTPClient
	}
	return value, nil
}
func parsePendingKey(raw string) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || len(rest) != 0 {
		return nil, ErrHTTPClient
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return nil, ErrHTTPClient
	}
	return key, nil
}
func atomicJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrHTTPClient
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".atomic-")
	if err != nil {
		return ErrHTTPClient
	}
	name := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			os.Remove(name)
		}
	}()
	if tmp.Chmod(0600) != nil {
		return ErrHTTPClient
	}
	if _, err = tmp.Write(raw); err != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrHTTPClient
	}
	if err = os.Rename(name, path); err != nil {
		return ErrHTTPClient
	}
	committed = true
	if d, e := os.Open(dir); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
func publishIdentityGeneration(certDir string, p pendingRotation, result enrollment.Result) error {
	root := filepath.Join(certDir, "fleet-identities")
	if err := os.MkdirAll(root, 0700); err != nil {
		return ErrHTTPClient
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrHTTPClient
	}
	stage, err := os.MkdirTemp(root, ".staging-")
	if err != nil {
		return ErrHTTPClient
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(stage)
		}
	}()
	if os.Chmod(stage, 0700) != nil {
		return ErrHTTPClient
	}
	if err = writeSecure(filepath.Join(stage, "host-key.pem"), []byte(p.KeyPEM)); err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return ErrHTTPClient
	}
	raw = append(raw, '\n')
	if err = writeSecure(filepath.Join(stage, "enrollment.json"), raw); err != nil {
		return err
	}
	target := filepath.Join(root, p.Generation)
	if _, err = os.Lstat(target); err == nil {
		existingResult, loadErr := loadResultFile(filepath.Join(target, "enrollment.json"))
		existingKey, keyErr := os.ReadFile(filepath.Join(target, "host-key.pem"))
		if loadErr != nil || keyErr != nil || !reflect.DeepEqual(existingResult, result) || !bytes.Equal(existingKey, []byte(p.KeyPEM)) {
			return ErrHTTPClient
		}
		// A prior process completed the immutable generation rename but crashed
		// before publishing the pointer. Reuse only the exact pending generation.
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrHTTPClient
	} else {
		if syncDirectory(stage) != nil {
			return ErrHTTPClient
		}
		if err = os.Rename(stage, target); err != nil {
			return ErrHTTPClient
		}
		committed = true
		if syncDirectory(root) != nil {
			return ErrHTTPClient
		}
	}
	return atomicJSON(filepath.Join(certDir, identityPointerName), p.Generation)
}
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(path)
	if err != nil {
		return ErrHTTPClient
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrHTTPClient
	}
	return nil
}
func writeSecure(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrHTTPClient
	}
	defer f.Close()
	if _, err = f.Write(value); err != nil || f.Sync() != nil {
		return ErrHTTPClient
	}
	return nil
}
