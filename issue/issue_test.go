package issue

import (
    "testing"
    "github.com/aniagut/msc-bbs-anonymous-credentials/models"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// MockPublicParameters creates a mock public parameters object for testing
func MockPublicParameters() models.PublicParameters {
    h1 := make([]e.G1, 5)
    for i := 0; i < 5; i++ {
        h1[i] = *e.G1Generator()
    }
    return models.PublicParameters{
        G1: e.G1Generator(),
        H1: h1,
    }
}

// MockSecretKey creates a mock secret key object for testing
func MockSecretKey() models.SecretKey {
	X := new(e.Scalar)
	X.SetUint64(12345)
    return models.SecretKey{
        X: X,
    }
}

// Test for successful credential issuance
func TestIssue_Success(t *testing.T) {
    attributes := []string{"attribute1", "attribute2", "attribute3", "attribute4", "attribute5"}
    publicParams := MockPublicParameters()
    secretKey := MockSecretKey()

    signature, err := Issue(attributes, publicParams, secretKey)

    assert.NoError(t, err, "Expected no error during credential issuance")
    assert.NotNil(t, signature.A, "Signature component A should not be nil")
    assert.NotNil(t, signature.E, "Signature component E should not be nil")
}

// Test for invalid attributes (empty list)
func TestIssue_InvalidAttributes(t *testing.T) {
    attributes := []string{}
    publicParams := MockPublicParameters()
    secretKey := MockSecretKey()

    _, err := Issue(attributes, publicParams, secretKey)

    assert.Error(t, err, "Expected an error for empty attributes")
}