package issue

import (
	"log"
	"errors"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Issue generates credential for a given list of attributes.
//
// Parameters:
//   - a: The list of attributes to be signed.
//   - publicParams: The public parameters of the system.
//   - privateKey: The private key of the system.

// Returns:
//   - Signature: The generated signature.
//   - error: An error if the signing process fails.
func Issue(a []string, publicParams models.PublicParameters, secretKey models.SecretKey) (models.Signature, error) {
	// Step 1: Generate the signature
	signature, err := Sign(publicParams, secretKey, a)
	if err != nil {
		log.Printf("Error generating signature: %v", err)
		return models.Signature{}, err
	}

	return signature, nil
}

// Sign generates a BBS++ signature for a given message.
//
// Parameters:
//   - publicParams: The public key of the system.
//   - signingKey: The key used for signing the message.
//   - a: The list of attributes to be signed.
//
// Returns:
//   - Signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicParams models.PublicParameters, signingKey models.SecretKey, a []string) (models.Signature, error) {
	// Step 1: Compute commitment C ← g1 * ∏_i h₁[i]^m[i]
	C, err := utils.ComputeCommitment(a, publicParams.H1, publicParams.G1)
    if err != nil {
        return models.Signature{}, err
    }

	// Step 2: Set random elem ← Z_p* and ensure x + e ≠ 0
	elem := new(e.Scalar)
	for {
		randomScalar, err := utils.RandomScalar()
		if err != nil {
			return models.Signature{}, errors.New("failed to generate random scalar e")
		}

		// Check if x + e ≠ 0
		check := new(e.Scalar)
		check.Add(signingKey.X, &randomScalar)
		if check.IsZero() == 0 {
			elem.Set(&randomScalar)
			break
		}
	}

	// Step 3: Compute signature component A <- C^{1 / (x + e)} ∈ G_1
	A := computeA(signingKey.X, elem, C)

	// Step 4: Return the signature σ = (A, e)
	return models.Signature{
		A: A,
		E: elem,
	}, nil
}

// ComputeA computes the signature component A = C^{1 / (x + e)} ∈ G_1
func computeA(x *e.Scalar, elem *e.Scalar, C *e.G1) *e.G1 {
	// Compute x + e
	x_plus_e := new(e.Scalar)
	x_plus_e.Add(x, elem)

	// Compute the inverse of (x + e)
	x_plus_e.Inv(x_plus_e)

	// Compute A = C^{1 / (x + e)}
	A := new(e.G1)
	A.ScalarMult(x_plus_e, C)
	return A
}
