package verify

import (
    "testing"

    "github.com/aniagut/msc-bbs-anonymous-credentials/models"
    "github.com/aniagut/msc-bbs-anonymous-credentials/utils"

    e "github.com/cloudflare/circl/ecc/bls12381"
)

func TestVerify_Success(t *testing.T) {
    // Setup generators
    G1 := e.G1Generator()
    G2 := e.G2Generator()

    // Scalars
    r := new(e.Scalar)
    r.SetUint64(12345)
    x := new(e.Scalar)
    x.SetUint64(67890)
    vE := new(e.Scalar)
    vE.SetUint64(12345)
    vR := new(e.Scalar)
    vR.SetUint64(67890)
    vI := make([]e.Scalar, 1)
    vI[0].SetUint64(11111)

    // Setup attribute structures
    revealedAttributes := []string{"testValue"}
    attributes := []string{"testValue", "hiddenValue"}
    hiddenAttributes := []string{"hiddenValue"}
    revealedIndices := []int{0}
    nonce := []byte("randomNonce123")

    // Create G1 points
    C, _ := utils.ComputeCommitment(attributes, []e.G1{*G1, *G1}, G1)
    elem := new(e.Scalar)
    elem.SetUint64(12345)
    A := new(e.G1)
    xPlusE := new(e.Scalar)
    xPlusE.Add(x, elem)
    xPlusE.Inv(xPlusE)
    A.ScalarMult(xPlusE, C)
    
    APrim := new(e.G1)
    APrim.ScalarMult(r, A)
    
    BPrim := new(e.G1)
    BPrim.ScalarMult(r, C)
    minusE := new(e.Scalar)
    *minusE = *elem
    minusE.Neg()
    APrimMinusE := new(e.G1)
    APrimMinusE.ScalarMult(minusE, APrim)
    BPrim.Add(BPrim, APrimMinusE)
    CRev, _ := utils.ComputeCommitment(revealedAttributes, []e.G1{*G1}, G1) // reuse G1 for simplicity
    hiddenH1Exp, _ := utils.ComputeH1Exp([]e.G1{*G1}, vI)

    // Compute U = CRev^vR * APrim^vE * hiddenH1Exp
    CRevExp := new(e.G1)
    CRevExp.ScalarMult(vR, CRev)
    APrimExp := new(e.G1)
    APrimExp.ScalarMult(vE, APrim)
    U := new(e.G1)
    U.Add(CRevExp, APrimExp)
    U.Add(U, hiddenH1Exp)

    // Compute real challenge
    ch, err := utils.ComputeChallenge(nonce, U, APrim, BPrim, revealedAttributes)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }

    // Compute z values
    zR := new(e.Scalar)
    zR.Mul(&ch, r)
    zR.Add(zR, vR)
    zE := new(e.Scalar)
    zE.Mul(&ch, elem)
    zE.Neg()
    zE.Add(zE, vE)
    zI := make([]e.Scalar, len(hiddenAttributes))
    for i := 0; i < len(hiddenAttributes); i++ {
        zI[i].Mul(&ch, r)
        aScalar := new(e.Scalar)
        aScalar.SetBytes(utils.SerializeString(hiddenAttributes[i]))
        zI[i].Mul(&zI[i], aScalar)
        zI[i].Add(&zI[i], &vI[i])
    }

    // Prepare proof
    proof := models.SignatureProof{
        APrim: APrim,
        BPrim: BPrim,
        Ze:    zE,
        Zr:    zR,
        Zi:    zI,
        Ch:    &ch,
    }

    // Public params and key
    publicParams := models.PublicParameters{
        G1: G1,
        G2: G2,
        H1: []e.G1{*G1, *G1},
    }

    x2 := new(e.G2)
    x2.ScalarMult(x, G2)
    publicKey := models.PublicKey{
        X2: x2,
    }

    // Run verify
    valid, err := Verify(proof, nonce, revealedAttributes, revealedIndices, publicParams, publicKey)
    if err != nil {
        t.Fatalf("Expected valid proof but got error: %v", err)
    }
    if !valid {
        t.Fatalf("Expected proof to verify but it failed")
    }
}