package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
    "fmt"
    "crypto/sha256"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// RandomG1Element generates a random element in the elliptic curve group G1.
func RandomG1Element() (e.G1, error) {
    var h e.G1
    randomBytes := make([]byte, 48)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return e.G1{}, errors.New("failed to generate random input for hashing to G1")
    }

    // Hash the random bytes to the curve using a domain separation tag
    h.Hash(randomBytes, []byte("domain-separation-tag"))
    return h, nil
}

// GenerateLRandomG1Elements generates l random elements in G1.
func GenerateLRandomG1Elements(l int) ([]e.G1, error) {
	elements := make([]e.G1, l)
	for i := 0; i < l; i++ {
		element, err := RandomG1Element()
		if err != nil {
			return nil, err
		}
		elements[i] = element
	}
	return elements, nil
}

// RandomScalar generates a random scalar in Z_p* (the field of scalars modulo the curve order).
func RandomScalar() (e.Scalar, error) {
    order := OrderAsBigInt()
    bigIntScalar, err := rand.Int(rand.Reader, order)
    if err != nil {
        return e.Scalar{}, errors.New("failed to generate random scalar")
    }

    if bigIntScalar.Sign() == 0 { // Ensure it's nonzero
        return RandomScalar()
    }

    // Convert to a scalar
    var scalar e.Scalar
    scalar.SetBytes(bigIntScalar.Bytes())
    return scalar, nil
}

// OrderAsBigInt returns the order of the elliptic curve as a big.Int.
func OrderAsBigInt() *big.Int {
    return new(big.Int).SetBytes(e.Order())
}

// Serialize string to bytes
func SerializeString(s string) []byte {
	return []byte(s)
}

// ComputeCommitment computes the commitment C for a given message M.
func ComputeCommitment(M []string, h1 []e.G1, g1 *e.G1) (*e.G1, error) {
	// Ensure the message vector length matches the length of h1
    if len(M) != len(h1) {
        return nil, errors.New("message vector length does not match h1 length")
    }

	// Initialize the commitment C with g1
	C := new(e.G1)
	*C = *g1

	for i, message := range M {
		// Convert message to a scalar
		mScalar := new(e.Scalar)
		mScalar.SetBytes(SerializeString(message))

		// Compute h1[i]^m[i]
        h1Exp := new(e.G1)
        h1Exp.ScalarMult(mScalar, &h1[i])

        // Multiply the result into the commitment
        C.Add(C, h1Exp)
	}

	return C, nil
}

// ComputeH1Exp computes the exponentiation of h1[i] by v[i] for each attribute.
// It returns the sum of these exponentiations.
func ComputeH1Exp(h1 []e.G1, v []e.Scalar) (*e.G1, error) {
    // Ensure the attributes vector length matches the length of h1
    if len(v) != len(h1) {
        return nil, errors.New("attributes vector length does not match h1 length")
    }

    // Initialize the result
    result := new(e.G1)
    result.SetIdentity()

    for i, val := range v {
        // Compute h1[i]^v[i]
        h1Exp := new(e.G1)
        h1Exp.ScalarMult(&val, &h1[i])

        result.Add(result, h1Exp)
    }

    return result, nil
}


// HashToScalar hashes a series of byte slices into a scalar in Z_p*.
func HashToScalar(inputs ...[]byte) (e.Scalar, error) {
    hash := sha256.New()

    // Write each input to the hash
    for _, input := range inputs {
        _, err := hash.Write(input)
        if err != nil {
            return e.Scalar{}, errors.New("failed to hash input")
        }
    }
    digest := hash.Sum(nil)

    // Convert hash output into a scalar
    var scalar e.Scalar
    order := new(big.Int).SetBytes(e.Order())
    bigIntScalar := new(big.Int).SetBytes(digest)
    bigIntScalar.Mod(bigIntScalar, order) // Ensure it is in Z_p
    scalar.SetBytes(bigIntScalar.Bytes())
    
    return scalar, nil
}

// Serialize G1 element to bytes
func SerializeG1(g *e.G1) []byte {
    return g.Bytes()
}

// SerializeListStrings serializes a list of strings into a byte slice.
func SerializeListStrings(list []string) []byte {
    var result []byte
    for _, str := range list {
        result = append(result, SerializeString(str)...)
    }
    return result
}

// ComputeChallenge computes the challenge scalar for the zero-knowledge proof.
func ComputeChallenge(nonce []byte, U *e.G1, A_prim *e.G1, B_prim *e.G1, a_i []string) (e.Scalar, error) {
    // Serialize the inputs
    attributes_serialized := SerializeListStrings(a_i)
    
    hash, err := HashToScalar(nonce, SerializeG1(U), SerializeG1(A_prim), SerializeG1(B_prim), attributes_serialized)
    if err != nil {
        return e.Scalar{}, errors.New("failed to compute challenge")
    }
    return hash, nil
}
// ComputeRevealedAndHiddenH computes the h values for the given revealed and hidden attributes.
func ComputeRevealedAndHiddenH(h1 []e.G1, revealed []int) ([]e.G1, []e.G1, error) {
	if len(revealed) == 0 {
		return nil, nil, fmt.Errorf("no revealed attributes provided")
	}
	if len(revealed) > len(h1) {
		return nil, nil, fmt.Errorf("revealed attributes exceed total attributes")
	}
	// Check if revealed indexes are valid
	for _, index := range revealed {
		if index < 0 || index >= len(h1) {
			return nil, nil, fmt.Errorf("revealed index %d out of bounds", index)
		}
	}
	
	// Create a map for quick lookup of revealed indexes
    revealedMap := make(map[int]bool, len(revealed))
    for _, index := range revealed {
        revealedMap[index] = true
    }

    // Create slices for revealed and hidden h values
    revealedH := make([]e.G1, 0, len(revealed))
    hiddenH := make([]e.G1, 0, len(h1)-len(revealed))

    for i, h := range h1 {
        if revealedMap[i] {
            revealedH = append(revealedH, h)
        } else {
            hiddenH = append(hiddenH, h)
        }
    }

    return revealedH, hiddenH, nil
}