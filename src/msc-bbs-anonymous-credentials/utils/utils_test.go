package utils

import (
    "testing"

    "github.com/stretchr/testify/assert"
    e "github.com/cloudflare/circl/ecc/bls12381"
)

// Test for RandomG1Element
func TestRandomG1Element(t *testing.T) {
    element, err := RandomG1Element()

    assert.NoError(t, err, "Expected no error during random G1 element generation")
    assert.NotNil(t, element, "Generated G1 element should not be nil")
}

// Test for GenerateLRandomG1Elements
func TestGenerateLRandomG1Elements(t *testing.T) {
    l := 5
    elements, err := GenerateLRandomG1Elements(l)

    assert.NoError(t, err, "Expected no error during random G1 elements generation")
    assert.Equal(t, l, len(elements), "Expected the correct number of G1 elements")
}

// Test for RandomScalar
func TestRandomScalar(t *testing.T) {
    scalar, err := RandomScalar()

    assert.NoError(t, err, "Expected no error during random scalar generation")
    assert.NotNil(t, scalar, "Generated scalar should not be nil")
}

// Test for SerializeString
func TestSerializeString(t *testing.T) {
    str := "test"
    serialized := SerializeString(str)

    assert.Equal(t, []byte(str), serialized, "Serialized string should match the input string")
}

// Test for SerializeListStrings
func TestSerializeListStrings(t *testing.T) {
    list := []string{"attribute1", "attribute2", "attribute3"}
    serialized := SerializeListStrings(list)

    expected := append(append([]byte("attribute1"), []byte("attribute2")...), []byte("attribute3")...)
    assert.Equal(t, expected, serialized, "Serialized list of strings should match the expected byte slice")
}

// Test for ComputeCommitment
func TestComputeCommitment(t *testing.T) {
    messages := []string{"message1", "message2"}
    h1 := make([]e.G1, len(messages))
    for i := range h1 {
        h1[i] = *e.G1Generator()
    }
    g1 := e.G1Generator()

    commitment, err := ComputeCommitment(messages, h1, g1)

    assert.NoError(t, err, "Expected no error during commitment computation")
    assert.NotNil(t, commitment, "Commitment should not be nil")
}

// Test for ComputeH1Exp
func TestComputeH1Exp(t *testing.T) {
	v := make([]e.Scalar, 2)
	for i := range v {
		v[i] = *new(e.Scalar)
		v[i].SetUint64(uint64(i + 1))
	}
    h1 := []e.G1{*e.G1Generator(), *e.G1Generator()}

    result, err := ComputeH1Exp(h1, v)

    assert.NoError(t, err, "Expected no error during H1 exponentiation computation")
    assert.NotNil(t, result, "Result of H1 exponentiation should not be nil")
}

// Test for HashToScalar
func TestHashToScalar(t *testing.T) {
    inputs := [][]byte{[]byte("input1"), []byte("input2")}
    scalar, err := HashToScalar(inputs...)

    assert.NoError(t, err, "Expected no error during hash to scalar computation")
    assert.NotNil(t, scalar, "Hash to scalar result should not be nil")
}

// Test for ComputeChallenge
func TestComputeChallenge(t *testing.T) {
    nonce := []byte("random_nonce")
    U := e.G1Generator()
    A_prim := e.G1Generator()
    B_prim := e.G1Generator()
    attributes := []string{"attribute1", "attribute2"}

    challenge, err := ComputeChallenge(nonce, U, A_prim, B_prim, attributes)

    assert.NoError(t, err, "Expected no error during challenge computation")
    assert.NotNil(t, challenge, "Challenge scalar should not be nil")
}

// Test for ComputeRevealedAndHiddenH
func TestComputeRevealedAndHiddenH(t *testing.T) {
    h1 := []e.G1{*e.G1Generator(), *e.G1Generator(), *e.G1Generator()}
    revealed := []int{0, 2}

    revealedH, hiddenH, err := ComputeRevealedAndHiddenH(h1, revealed)

    assert.NoError(t, err, "Expected no error during revealed and hidden H computation")
    assert.Equal(t, 2, len(revealedH), "Expected correct number of revealed H elements")
    assert.Equal(t, 1, len(hiddenH), "Expected correct number of hidden H elements")
}