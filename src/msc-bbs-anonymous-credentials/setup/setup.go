package setup

import (
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"errors"
	e "github.com/cloudflare/circl/ecc/bls12381"
)
	
// Setup initializes the public parameters and keys for the BBS++ system.
// It generates the generators g1 and g2, independent generators h_1[1..l], and the secret key x.
// The function returns the public parameters, public key, and secret key.
//
// Parameters:
//   - l: The number of independent generators to be generated.
//
// Returns:
//   - models.SetupResult: The result containing public parameters, public key, and secret key.
//   - error: An error if the setup process fails.
//
func Setup(l int) (models.SetupResult, error) {
	// Step 0: Validate input
	if l <= 0 {
		return models.SetupResult{}, errors.New("number of independent generators must be greater than 0")
	}
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()

	// 2. Select random h_1[1..l] ← independent generators of G1
	h1, err:= utils.GenerateLRandomG1Elements(l)
	if err != nil {
		return models.SetupResult{}, err
	}

	// 3. Select random x ∈ Zp*
	x, err := utils.RandomScalar()
	if err != nil {
		return models.SetupResult{}, err
	}

	// 4. Compute verification key vk = X₂ ← g₂^x
	X2 := new(e.G2)
	X2.ScalarMult(&x, g2)

	// Return the result
	return models.SetupResult{
		PublicParameters: models.PublicParameters{
			G1: g1,
			G2: g2,
			H1: h1,
		},
		PublicKey: models.PublicKey{
			X2: X2,
		},
		SecretKey: models.SecretKey{
			X: &x,
		},
	}, nil
}