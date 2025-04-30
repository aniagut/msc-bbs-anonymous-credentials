package presentation

import (
	"fmt"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"log"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Presentation presents attributes and generates a proof of knowledge of the valid credential for the given attributes (both revealed and non-revealed).
// It uses the BBS+ signature scheme to create a zero-knowledge proof of knowledge of the valid credential for the given attributes.
// The function takes the attributes, credential, revealed attributes, and public parameters as input.
// It returns a proof of knowledge of the valid credential for the given attributes.
// Arguments:
//   - attributes: The list of attributes to be presented.
//   - credential: The BBS+ signature representing the credential.
//   - revealed: The list of indexes for revealed attributes.
//   - publicParams: The public parameters of the system.
//   - nonce: A random nonce used for the proof.
// Returns:
//   - SignatureProof: The generated proof of knowledge of the valid credential for the given attributes.
//   - error: An error if the presentation process fails.
func Presentation(attributes []string, credential models.Signature, revealed []int, publicParams models.PublicParameters, nonce []byte) (models.SignatureProof, error){
	// Step 1: Compute the revealed and hidden attributes
	revealedAttributes, hiddenAttributes, err := ComputeRevealedAndHiddenAttributes(attributes, revealed)
	if err != nil {
		log.Printf("Error computing revealed and hidden attributes: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 2: Compute h values h₁[i] ← g1^m[i] for revealed and hidden attributes a[i]
	revealedH, hiddenH, err := utils.ComputeRevealedAndHiddenH(publicParams.H1, revealed)
	if err != nil {
		log.Printf("Error computing revealed and hidden h values: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 3: Compute the commitment for revealed attributes C_rev ← g1 * ∏_i h₁[i]^a[i]
	// where m[i] is the i-th revealed attribute.
	C_rev, err := utils.ComputeCommitment(revealedAttributes, revealedH, publicParams.G1)
	if err != nil {
		log.Printf("Error computing commitment: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 4: Select random r ← Z_p*
	r, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar r: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 5: Compute the signature component A_prim ← A^r
	A_prim := new(e.G1)
	A_prim.ScalarMult(&r, credential.A)

	// Step 6: Compute the signature component B_prim = C^r * A^(-re)
	B_prim, err := ComputeBPrim(attributes, A_prim, credential.E, publicParams, r)
	if err != nil {
		log.Printf("Error computing B_prim: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 7: Compute random scalars v_r, {v_j} for j ∈ hidden and v_e
	v_r, v_e, v_j, err := ComputeVValues(len(hiddenAttributes))
	if err != nil {
		log.Printf("Error generating random scalars: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 8: Compute U ← C_rev^v_r * ∏_j h₁[j]^v_j * A_prim^v_e for j ∈ hidden
	U, err := ComputeU(v_r, v_e, v_j, C_rev, A_prim, hiddenH)
	if err != nil {
		log.Printf("Error computing U: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 9: Compute the challenge ch ← H(nonce, U, A_prim, B_prim, {a_i}) for i ∈ revealed
	ch, err := utils.ComputeChallenge(nonce, U, A_prim, B_prim, revealedAttributes)
	if err != nil {
		log.Printf("Error computing challenge: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 10: Blind v_r, {v_j} for j ∈ hidden and v_e
	z_r, z_e, z_j := ComputeZValues(v_r, v_e, v_j, credential.E, ch, r, hiddenAttributes)

	// Step 11: Return the proof of knowledge of the valid credential for the given attributes
	return models.SignatureProof{
		A_prim: A_prim,
		B_prim: B_prim,
		Ch:     &ch,
		Z_r:    z_r,
		Z_i:    z_j,
		Z_e:    z_e,
	}, nil
}

// ComputeRevealedAndHiddenAttributes computes the lists of hidden and revealed attributes based on the given indexes.
func ComputeRevealedAndHiddenAttributes(attributes []string, revealed []int) ([]string, []string, error) {
	if len(revealed) == 0 {
		return nil, nil, fmt.Errorf("no revealed attributes provided")
	}
	if len(revealed) > len(attributes) {
		return nil, nil, fmt.Errorf("revealed attributes exceed total attributes")
	}
	// Check if revealed indexes are valid
	for _, index := range revealed {
		if index < 0 || index >= len(attributes) {
			return nil, nil, fmt.Errorf("revealed index %d out of bounds", index)
		}
	}
	
	// Create a map for quick lookup of revealed indexes
    revealedMap := make(map[int]bool, len(revealed))
    for _, index := range revealed {
        revealedMap[index] = true
    }

    // Create slices for revealed and hidden attributes
    revealedAttributes := make([]string, 0, len(revealed))
    hiddenAttributes := make([]string, 0, len(attributes)-len(revealed))

    for i, attr := range attributes {
        if revealedMap[i] {
            revealedAttributes = append(revealedAttributes, attr)
        } else {
            hiddenAttributes = append(hiddenAttributes, attr)
        }
    }

    return revealedAttributes, hiddenAttributes, nil
}

// ComputeBPrim computes the second component of the proof B_prim = C^r * A^(-re).
func ComputeBPrim(attributes []string, A_prim *e.G1, elem *e.Scalar, publicParams models.PublicParameters, r e.Scalar) (*e.G1, error) {
	// Step 1: Compute the commitment C ← g1 * ∏_i h₁[i]^m[i]
	// where m[i] is the i-th attribute.
	C, err := utils.ComputeCommitment(attributes, publicParams.H1, publicParams.G1)
	if err != nil {
		log.Printf("Error computing commitment: %v", err)
		return nil, err
	}
	// Step 2: Compute C^r
	C_exp := new(e.G1)
	C_exp.ScalarMult(&r, C)

	// Step 3: Compute A^(-re)
	e_neg := new(e.Scalar)
	*e_neg = *elem
	e_neg.Neg()
	A_prim_exp := new(e.G1)
	A_prim_exp.ScalarMult(e_neg, A_prim)

	// Step 4: Compute B_prim = C^r * A^(-re)
	B_prim := new(e.G1)
	B_prim.Add(C_exp, A_prim_exp)

	// Step 5: Return B_prim
	return B_prim, nil
}

// ComputeVValues computes random scalars v_r, v_e, and {v_j} for j ∈ hidden.
func ComputeVValues(hiddenAttrLen int) (e.Scalar, e.Scalar, []e.Scalar, error) {
	// Step 1. Compute random scalar v_r <- Z_p*
	v_r, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar v_r: %v", err)
		return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
	}

	// Step 2. Compute random scalar v_e <- Z_p*
	v_e, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar v_e: %v", err)
		return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
	}

	// Step 3. Compute random scalars {v_j} <- Z_p* for j ∈ hidden
	v_j := make([]e.Scalar, hiddenAttrLen)
	for i := 0; i < hiddenAttrLen; i++ {
		v_j[i], err = utils.RandomScalar()
		if err != nil {
			log.Printf("Error generating random scalar v_j[%d]: %v", i, err)
			return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
		}
	}
	return v_r, v_e, v_j, nil
}

// ComputeU computes U ← C_rev^v_r * ∏_j h₁[j]^v_j * A_prim^v_e for j ∈ hidden.
func ComputeU(v_r e.Scalar, v_e e.Scalar, v_j []e.Scalar, C_rev *e.G1, A_prim *e.G1, hiddenH []e.G1) (*e.G1, error) {
	// Step 1: Compute C_rev^v_r
	C_rev_exp_v_r := new(e.G1)
	C_rev_exp_v_r.ScalarMult(&v_r, C_rev)

	// Step 2: Compute ∏_j h₁[j]^v_j for j ∈ hidden
	h1Exp_v_j, err := utils.ComputeH1Exp(hiddenH, v_j)
	if err != nil {
		log.Printf("Error computing hidden h1 exponent: %v", err)
		return nil, err
	}
	// Step 3: Compute A_prim^v_e
	A_prim_exp_v_e := new(e.G1)
	A_prim_exp_v_e.ScalarMult(&v_e, A_prim)

	// Step 4: Compute U ← C_rev^v_r * ∏_j h₁[j]^v_j * A_prim^v_e for j ∈ hidden
	U := new(e.G1)
	U.Add(C_rev_exp_v_r, h1Exp_v_j)
	U.Add(U, A_prim_exp_v_e)

	// Step 5: Return U
	return U, nil
}

// ComputeZValues computes z_r, z_e, and {z_j} for j ∈ hidden.
// It uses the challenge ch and the random scalar r to blind the values.
func ComputeZValues(v_r e.Scalar, v_e e.Scalar, v_j []e.Scalar, elem *e.Scalar, ch e.Scalar, r e.Scalar, hiddenAttributes []string) (*e.Scalar, *e.Scalar, []e.Scalar) {
	// Step 1: Compute z_r ← v_r + ch * e
	z_r := new(e.Scalar)
	z_r.Mul(&ch, &r)
	z_r.Add(z_r, &v_r)

	// Step 2: Compute z_e <- v_e - ch * e
	z_e := new(e.Scalar)
	z_e.Mul(&ch, elem)
	z_e.Neg()
	z_e.Add(z_e, &v_e)

	// Step 3: Compute z_j <- v_j + ch * r *  a_j for j ∈ hidden
	z_j := make([]e.Scalar, len(hiddenAttributes))
	for i := 0; i < len(hiddenAttributes); i++ {
		z_j[i].Mul(&ch, &r)
		aScalar := new(e.Scalar)
        aScalar.SetBytes(utils.SerializeString(hiddenAttributes[i]))
		z_j[i].Mul(&z_j[i], aScalar)
		z_j[i].Add(&z_j[i], &v_j[i])
	}
	
	// Step 4: Return z_r, z_j, and z_e
	return z_r, z_e, z_j
}