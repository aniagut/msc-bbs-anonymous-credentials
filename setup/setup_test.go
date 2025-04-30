package setup

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

// Test for successful setup
func TestSetup_Success(t *testing.T) {
    l := 5 // Number of independent generators
    result, err := Setup(l)

    assert.NoError(t, err, "Expected no error during setup")
    assert.NotNil(t, result.PublicParameters.G1, "G1 generator should not be nil")
    assert.NotNil(t, result.PublicParameters.G2, "G2 generator should not be nil")
    assert.Equal(t, l, len(result.PublicParameters.H1), "H1 should have the correct number of generators")
    assert.NotNil(t, result.PublicKey.X2, "Public key X2 should not be nil")
    assert.NotNil(t, result.SecretKey.X, "Secret key X should not be nil")
}

// Test for invalid input (l = 0)
func TestSetup_InvalidInput(t *testing.T) {
    l := 0 // Invalid number of generators
    _, err := Setup(l)

    assert.Error(t, err, "Expected an error for invalid input (l = 0)")
}