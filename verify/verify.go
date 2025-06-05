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
//   - zkpProof: The zero-knowledge proof to be verified.
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
func Verify(zkpProof models.SignatureProof, nonce []byte, revealedAttributes []string, revealedIndices []int, publicParams models.PublicParameters, publicKey models.PublicKey) (bool, error) {
    // Step 1: Compute the h values h₁[i] ← g1^m[i] for revealed and hidden attributes a[i]
    revealedH, hiddenH, err := utils.ComputeRevealedAndHiddenH(publicParams.H1, revealedIndices)
    if err != nil {
        log.Printf("Error computing revealed and hidden h values: %v", err)
        return false, err
    }

    // Step 2: Compute ∏_j h₁[j]^z_j for j ∈ hidden
    // where z_j is the j-th revealed hidden.
    hiddenH1Exp, err := utils.ComputeH1Exp(hiddenH, zkpProof.Zi)
    if err != nil {
        log.Printf("Error computing hidden h1 exponent: %v", err)
        return false, err
    }

    // Step 3: Compute the commitment for revealed attributes CRev ← g1 * ∏_i h₁[i]^a[i]
    CRev, err := utils.ComputeCommitment(revealedAttributes, revealedH, publicParams.G1)
    if err != nil {
        log.Printf("Error computing commitment: %v", err)
        return false, err
    }

    // Step 4: Recompute U ← CRev^Zr * ∏_j h₁[j]^Zi * APrim^Ze * BPrim^(-ch) for j ∈ hidden
    U := ComputeU(zkpProof, CRev, hiddenH1Exp)

    // Step 5: Recompute the challenge scalar ch ← H(nonce, U, APrim, BPrim, {a_j}) for j ∈ revealed
    ch, err := utils.ComputeChallenge(nonce, U, zkpProof.APrim, zkpProof.BPrim, revealedAttributes)
    if err != nil {
        log.Printf("Error computing hash to scalar: %v", err)
        return false, err
    }

    // Step 6: Verify that the recomputed challenge ch matches the signature's challenge
    if ch.IsEqual(zkpProof.Ch) != 1 {
        log.Printf("Challenge mismatch: expected %v, got %v", zkpProof.Ch, ch)
        return false, errors.New("challenge mismatch")
    }
    log.Printf("Challenge verified successfully")

    // Step 7: Verify the credential
    // Check if e(APrim, publicKey.X2) == e(BPrim, publicParams.G2)
    if !PairingCheck(zkpProof.APrim, publicKey.X2, zkpProof.BPrim, publicParams.G2) {
        log.Printf("Pairing check failed: e(APrim, publicKey.X2) != e(BPrim, publicParams.G2)")
        return false, errors.New("pairing check failed")
    }
    
    // Step 8: Credentials are valid, return true
    log.Printf("Credential verification successful")
    return true, nil
}

// PairingCheck performs the pairing check for the given inputs.
func PairingCheck(aPrim *e.G1, x2 *e.G2, bPrim *e.G1, g2 *e.G2) bool {
    // Compute the pairing e(APrim, X2)
    pairing1 := e.Pair(aPrim, x2)

    // Compute the pairing e(BPrim, G2)
    pairing2 := e.Pair(bPrim, g2)

    // Check if the pairings are equal
    if pairing1.IsEqual(pairing2) == false {
        return false
    }
    log.Printf("Pairing check passed: e(APrim, X2) == e(BPrim, G2)")
    return true
}

func ComputeU(zkpProof models.SignatureProof, cRev *e.G1, hiddenH1Exp *e.G1) *e.G1 {
    // Step 1: Compute CRev^Zr
    cRevExp := new(e.G1)
    cRevExp.ScalarMult(zkpProof.Zr, cRev)

    // Step 2: Compute APrim^Ze
    aPrimExp := new(e.G1)
    aPrimExp.ScalarMult(zkpProof.Ze, zkpProof.APrim)

    // Step 3: Compute BPrim^(-ch)
    negCh := new(e.Scalar)
    *negCh = *zkpProof.Ch
    negCh.Neg()
    bExp := new(e.G1)
    bExp.ScalarMult(negCh, zkpProof.BPrim)

    // Step 4: Compute U ← CRev^Zr * ∏_j h₁[j]^Zi * APrim^Ze * BPrim^(-ch) for j ∈ hidden
    U := new(e.G1)
    U.Add(cRevExp, hiddenH1Exp)
    U.Add(U, aPrimExp)
    U.Add(U, bExp)

    // Step 5: Return U
    return U
}