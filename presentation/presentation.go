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
    CRev, err := utils.ComputeCommitment(revealedAttributes, revealedH, publicParams.G1)
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

    // Step 5: Compute the signature component APrim ← A^r
    APrim := new(e.G1)
    APrim.ScalarMult(&r, credential.A)

    // Step 6: Compute the signature component BPrim = C^r * A^(-re)
    BPrim, err := ComputeBPrim(attributes, APrim, credential.E, publicParams, r)
    if err != nil {
        log.Printf("Error computing BPrim: %v", err)
        return models.SignatureProof{}, err
    }

    // Step 7: Compute random scalars vR, vE, {vJ} for j ∈ hidden
    vR, vE, vJ, err := ComputeVValues(len(hiddenAttributes))
    if err != nil {
        log.Printf("Error generating random scalars: %v", err)
        return models.SignatureProof{}, err
    }

    // Step 8: Compute U ← CRev^vR * ∏_j h₁[j]^vJ * APrim^vE for j ∈ hidden
    U, err := ComputeU(vR, vE, vJ, CRev, APrim, hiddenH)
    if err != nil {
        log.Printf("Error computing U: %v", err)
        return models.SignatureProof{}, err
    }

    // Step 9: Compute the challenge ch ← H(nonce, U, APrim, BPrim, {a_i}) for i ∈ revealed
    ch, err := utils.ComputeChallenge(nonce, U, APrim, BPrim, revealedAttributes)
    if err != nil {
        log.Printf("Error computing challenge: %v", err)
        return models.SignatureProof{}, err
    }

    // Step 10: Blind vR, {vJ} for j ∈ hidden and vE
    zR, zE, zJ := ComputeZValues(vR, vE, vJ, credential.E, ch, r, hiddenAttributes)

    // Step 11: Return the proof of knowledge of the valid credential for the given attributes
    return models.SignatureProof{
        APrim: APrim,
        BPrim: BPrim,
        Ch:    &ch,
        Zr:    zR,
        Zi:    zJ,
        Ze:    zE,
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

// ComputeBPrim computes the second component of the proof BPrim = C^r * A^(-re).
func ComputeBPrim(attributes []string, APrim *e.G1, elem *e.Scalar, publicParams models.PublicParameters, r e.Scalar) (*e.G1, error) {
    // Step 1: Compute the commitment C ← g1 * ∏_i h₁[i]^m[i]
    // where m[i] is the i-th attribute.
    C, err := utils.ComputeCommitment(attributes, publicParams.H1, publicParams.G1)
    if err != nil {
        log.Printf("Error computing commitment: %v", err)
        return nil, err
    }
    // Step 2: Compute C^r
    CExp := new(e.G1)
    CExp.ScalarMult(&r, C)

    // Step 3: Compute A^(-re)
    eNeg := new(e.Scalar)
    *eNeg = *elem
    eNeg.Neg()
    APrimExp := new(e.G1)
    APrimExp.ScalarMult(eNeg, APrim)

    // Step 4: Compute BPrim = C^r * A^(-re)
    BPrim := new(e.G1)
    BPrim.Add(CExp, APrimExp)

    // Step 5: Return BPrim
    return BPrim, nil
}

// ComputeVValues computes random scalars vR, vE, and {vJ} for j ∈ hidden.
func ComputeVValues(hiddenAttrLen int) (e.Scalar, e.Scalar, []e.Scalar, error) {
    // Step 1. Compute random scalar vR <- Z_p*
    vR, err := utils.RandomScalar()
    if err != nil {
        log.Printf("Error generating random scalar vR: %v", err)
        return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
    }

    // Step 2. Compute random scalar vE <- Z_p*
    vE, err := utils.RandomScalar()
    if err != nil {
        log.Printf("Error generating random scalar vE: %v", err)
        return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
    }

    // Step 3. Compute random scalars {vJ} <- Z_p* for j ∈ hidden
    vJ := make([]e.Scalar, hiddenAttrLen)
    for i := 0; i < hiddenAttrLen; i++ {
        vJ[i], err = utils.RandomScalar()
        if err != nil {
            log.Printf("Error generating random scalar vJ[%d]: %v", i, err)
            return e.Scalar{}, e.Scalar{}, []e.Scalar{}, err
        }
    }
    return vR, vE, vJ, nil
}

// ComputeU computes U ← CRev^vR * ∏_j h₁[j]^vJ * APrim^vE for j ∈ hidden.
func ComputeU(vR e.Scalar, vE e.Scalar, vJ []e.Scalar, CRev *e.G1, APrim *e.G1, hiddenH []e.G1) (*e.G1, error) {
    // Step 1: Compute CRev^vR
    CRevExpVR := new(e.G1)
    CRevExpVR.ScalarMult(&vR, CRev)

    // Step 2: Compute ∏_j h₁[j]^vJ for j ∈ hidden
    h1ExpVJ, err := utils.ComputeH1Exp(hiddenH, vJ)
    if err != nil {
        log.Printf("Error computing hidden h1 exponent: %v", err)
        return nil, err
    }
    // Step 3: Compute APrim^vE
    APrimExpVE := new(e.G1)
    APrimExpVE.ScalarMult(&vE, APrim)

    // Step 4: Compute U ← CRev^vR * ∏_j h₁[j]^vJ * APrim^vE for j ∈ hidden
    U := new(e.G1)
    U.Add(CRevExpVR, h1ExpVJ)
    U.Add(U, APrimExpVE)

    // Step 5: Return U
    return U, nil
}

// ComputeZValues computes zR, zE, and {zJ} for j ∈ hidden.
// It uses the challenge ch and the random scalar r to blind the values.
func ComputeZValues(vR e.Scalar, vE e.Scalar, vJ []e.Scalar, elem *e.Scalar, ch e.Scalar, r e.Scalar, hiddenAttributes []string) (*e.Scalar, *e.Scalar, []e.Scalar) {
    // Step 1: Compute zR ← vR + ch * r
    zR := new(e.Scalar)
    zR.Mul(&ch, &r)
    zR.Add(zR, &vR)

    // Step 2: Compute zE <- vE - ch * e
    zE := new(e.Scalar)
    zE.Mul(&ch, elem)
    zE.Neg()
    zE.Add(zE, &vE)

    // Step 3: Compute zJ <- vJ + ch * r *  a_j for j ∈ hidden
    zJ := make([]e.Scalar, len(hiddenAttributes))
    for i := 0; i < len(hiddenAttributes); i++ {
        zJ[i].Mul(&ch, &r)
        aScalar := new(e.Scalar)
        aScalar.SetBytes(utils.SerializeString(hiddenAttributes[i]))
        zJ[i].Mul(&zJ[i], aScalar)
        zJ[i].Add(&zJ[i], &vJ[i])
    }
    
    // Step 4: Return zR, zJ, and zE
    return zR, zE, zJ
}