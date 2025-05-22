package issue

import (
	"log"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-plus-plus/sign"
	m "github.com/aniagut/msc-bbs-plus-plus/models"
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
	
	// Convert the parameters to the format expected by the BBS++ library
	publicParamsBBS := m.PublicParameters{
		G1: publicParams.G1,
		G2: publicParams.G2,
		H1: publicParams.H1,
	}
	secretKeyBBS := m.SigningKey{ 
		X: secretKey.X,
	}
	// Run Sign from the BBS++ library to generate the signature
	signatureBBS, err := sign.Sign(publicParamsBBS, secretKeyBBS, a)
	if err != nil {
		log.Printf("Error generating signature: %v", err)
		return models.Signature{}, err
	}

	// Convert the signature from the BBS++ library to the format expected by the models package
	signature := models.Signature{
		A: signatureBBS.A,
		E: signatureBBS.E,
	}

	return signature, nil
}
