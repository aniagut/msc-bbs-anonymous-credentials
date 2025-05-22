package setup

import (
	"github.com/aniagut/msc-bbs-plus-plus/keygen"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
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
	// Run KeyGen from the BBS++ library to generate the public parameters, public key and secret key
	result, err := keygen.KeyGen(l)
	if err != nil {
		return models.SetupResult{}, err
	}

	// Create the setup result struct
	setupResult := models.SetupResult{
		PublicParameters: models.PublicParameters{
			G1: result.PublicParameters.G1,
			G2: result.PublicParameters.G2,
			H1: result.PublicParameters.H1,
		},
		PublicKey: models.PublicKey{
			X2: result.VerificationKey.X2,
		},
		SecretKey: models.SecretKey{
			X: result.SigningKey.X,
		},
	}
	return setupResult, nil
}