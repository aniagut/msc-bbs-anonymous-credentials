package verify

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"log"
	"errors"
)

// Verify checks the validity of ZKP proof for a signature (ensures the credental was signed by the issuer) and binds the revealed attributes to the proof
// using the provided nonce and revealed attributes.
//
// Parameters:
//   - ZKPProof: The zero-knowledge proof to be verified.
//   - nonce: A random nonce used for the proof.
//   - revealedAttributes: The list of revealed attributes.
//   - revealedIndices: The list of indices for revealed attributes.
//   - publicParams: The public parameters of the system.
//   - publicKey: The public key of the system.
//
// Returns:
//   - bool: true if the proof is valid, false otherwise.
//   - error: An error if the verification process fails.
//
func Verify(ZKPProof models.SignatureProof, nonce []byte, revealedAttributes []string, revealedIndices []int, publicParams models.PublicParameters, publicKey models.PublicKey) (bool, error) {
	// Step 1: Compute the h values h₁[i] ← g1^m[i] for revealed and hidden attributes a[i]
	revealedH, hiddenH, err := utils.ComputeRevealedAndHiddenH(publicParams.H1, revealedIndices)
	if err != nil {
		log.Printf("Error computing revealed and hidden h values: %v", err)
		return false, err
	}

	// Step 2: Compute ∏_j h₁[j]^z_j for j ∈ hidden
	// where z_j is the j-th revealed hidden.
	hiddenH1Exp, err := utils.ComputeH1Exp(hiddenH, ZKPProof.Z_i)
	if err != nil {
		log.Printf("Error computing hidden h1 exponent: %v", err)
		return false, err
	}

	// Step 3: Compute the commitment for revealed attributes C_rev ← g1 * ∏_i h₁[i]^a[i]
	C_rev, err := utils.ComputeCommitment(revealedAttributes, revealedH, publicParams.G1)
	if err != nil {
		log.Printf("Error computing commitment: %v", err)
		return false, err
	}

	// Step 4: Recompute U ← C_rev^z_r * ∏_j h₁[j]^z_j * A_prim^z_e * B^(-ch) for j ∈ hidden
	U := ComputeU(ZKPProof, C_rev, hiddenH1Exp)

	// Step 5: Recompute the challenge scalar ch ← H(nonce, U, A_prim, B_prim, {a_j}) for j ∈ revealed
	ch, err := utils.ComputeChallenge(nonce, U, ZKPProof.A_prim, ZKPProof.B_prim, revealedAttributes)
	if err != nil {
		log.Printf("Error computing hash to scalar: %v", err)
		return false, err
	}

	// Step 6: Verify that the recomputed challenge ch matches the signature's challenge
	if ch.IsEqual(ZKPProof.Ch) != 1 {
		log.Printf("Challenge mismatch: expected %v, got %v", ZKPProof.Ch, ch)
		return false, errors.New("challenge mismatch")
	}
	log.Printf("Challenge verified successfully")

	// Step 7: Verify the credential
	// Check if e(A_prim, publicKey.X2) == e(B_prim, g2)
	if !PairingCheck(ZKPProof.A_prim, publicKey.X2, ZKPProof.B_prim, publicParams.G2) {
		log.Printf("Pairing check failed: e(A_prim, publicKey.X2) != e(B_prim, publicParams.G2)")
		return false, errors.New("pairing check failed")
	}
	
	// Step 8: Credentials are valid, return true
	log.Printf("Credential verification successful")
	return true, nil
}

// PairingCheck performs the pairing check for the given inputs.
func PairingCheck(A_prim *e.G1, X2 *e.G2, B_prim *e.G1, G2 *e.G2) bool {
	// Compute the pairing e(A_prim, X2)
	pairing1 := e.Pair(A_prim, X2)

	// Compute the pairing e(B_prim, G2)
	pairing2 := e.Pair(B_prim, G2)

	// Check if the pairings are equal
	if pairing1.IsEqual(pairing2) == false {
		return false
	}
	log.Printf("Pairing check passed: e(A_prim, X2) == e(B_prim, G2)")
	return true
}

func ComputeU(ZKPProof models.SignatureProof, C_rev *e.G1, hiddenH1Exp *e.G1) (*e.G1) {
	// Step 1: Compute C_rev^z_r
	C_rev_exp := new(e.G1)
	C_rev_exp.ScalarMult(ZKPProof.Z_r, C_rev)

	// Step 2: Compute A_prim^z_e
	A_prim_exp := new(e.G1)
	A_prim_exp.ScalarMult(ZKPProof.Z_e, ZKPProof.A_prim)

	// Step 3: Compute B^(-ch)
	neg_ch := new(e.Scalar)
	*neg_ch = *ZKPProof.Ch
	neg_ch.Neg()
	B_exp := new(e.G1)
	B_exp.ScalarMult(neg_ch, ZKPProof.B_prim)

	// Step 4: Compute U ← C_rev^z_r * ∏_j h₁[j]^z_j * A_prim^z_e * B^(-ch) for j ∈ hidden
	U := new(e.G1)
	U.Add(C_rev_exp, hiddenH1Exp)
	U.Add(U, A_prim_exp)
	U.Add(U, B_exp)

	// Step 5: Return U
	return U
}