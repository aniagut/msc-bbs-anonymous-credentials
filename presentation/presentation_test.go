package presentation

import (
    "testing"

    "github.com/aniagut/msc-bbs-anonymous-credentials/models"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// Helper function to generate mock public parameters
func mockPublicParameters() models.PublicParameters {
    h1 := make([]e.G1, 5)
    for i := 0; i < 5; i++ {
        h1[i] = *e.G1Generator()
    }
    return models.PublicParameters{
        G1: e.G1Generator(),
        H1: h1,
    }
}

// Helper function to generate a mock signature
func mockSignature() models.Signature {
	E := new(e.Scalar)
	E.SetUint64(12345)
    return models.Signature{
        A: e.G1Generator(),
        E: E,
    }
}

// Test for successful proof generation
func TestPresentation_Success(t *testing.T) {
    attributes := []string{"attribute1", "attribute2", "attribute3", "attribute4", "attribute5"}
    revealed := []int{0, 2}
    publicParams := mockPublicParameters()
    credential := mockSignature()
    nonce := []byte("random_nonce")

    proof, err := Presentation(attributes, credential, revealed, publicParams, nonce)

    assert.NoError(t, err, "Expected no error during proof generation")
    assert.NotNil(t, proof.A_prim, "A_prim should not be nil")
    assert.NotNil(t, proof.B_prim, "B_prim should not be nil")
    assert.NotNil(t, proof.Ch, "Challenge should not be nil")
    assert.NotNil(t, proof.Z_r, "Z_r should not be nil")
    assert.NotNil(t, proof.Z_e, "Z_e should not be nil")
    assert.NotNil(t, proof.Z_i, "Z_i should not be nil")
}

// Test for invalid revealed indices (out of bounds)
func TestPresentation_InvalidRevealedIndices(t *testing.T) {
    attributes := []string{"attribute1", "attribute2", "attribute3"}
    revealed := []int{0, 5} // Index 5 is out of bounds
    publicParams := mockPublicParameters()
    credential := mockSignature()
    nonce := []byte("random_nonce")

    _, err := Presentation(attributes, credential, revealed, publicParams, nonce)

    assert.Error(t, err, "Expected an error for out-of-bounds revealed indices")
}

// Test for empty attributes
func TestPresentation_EmptyAttributes(t *testing.T) {
    attributes := []string{}
    revealed := []int{}
    publicParams := mockPublicParameters()
    credential := mockSignature()
    nonce := []byte("random_nonce")

    _, err := Presentation(attributes, credential, revealed, publicParams, nonce)

    assert.Error(t, err, "Expected an error for empty attributes")
}