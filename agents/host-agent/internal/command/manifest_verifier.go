package command

import (
	"crypto/ecdsa"
	"crypto/sha256"
)

// ECDSAManifestVerifier pins one authorized manifest signer and P-256 key.
// Construction is explicit so artifact installation remains closed by default.
type ECDSAManifestVerifier struct {
	signerID string
	key      *ecdsa.PublicKey
}

func NewECDSAManifestVerifier(signerID string, key *ecdsa.PublicKey) (*ECDSAManifestVerifier, error) {
	if !identifier.MatchString(signerID) || key == nil || key.Curve == nil || key.Curve.Params().Name != "P-256" {
		return nil, ErrArtifactUnauthorized
	}
	return &ECDSAManifestVerifier{signerID: signerID, key: key}, nil
}
func (v *ECDSAManifestVerifier) AuthorizedSigner(signerID string) bool {
	return v != nil && signerID == v.signerID
}
func (v *ECDSAManifestVerifier) VerifyManifest(signerID string, payload, signature []byte) bool {
	if !v.AuthorizedSigner(signerID) {
		return false
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(v.key, digest[:], signature)
}

var _ ManifestVerifier = (*ECDSAManifestVerifier)(nil)
