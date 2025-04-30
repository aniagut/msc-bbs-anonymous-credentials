package verify_test

import (
	"testing"

	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"github.com/aniagut/msc-bbs-anonymous-credentials/verify"

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
	v_e := new(e.Scalar)
	v_e.SetUint64(12345)
	v_r := new(e.Scalar)
	v_r.SetUint64(67890)
	v_i := make([]e.Scalar, 1)
	v_i[0].SetUint64(11111)

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
	x_plus_e := new(e.Scalar)
	x_plus_e.Add(x, elem)
	x_plus_e.Inv(x_plus_e)
	A.ScalarMult(x_plus_e, C)
	
	A_prim := new(e.G1)
	A_prim.ScalarMult(r, A)
	
	B_prim := new(e.G1)
	B_prim.ScalarMult(r, C)
	minus_e := new(e.Scalar)
	*minus_e = *elem
	minus_e.Neg()
	A_prim_minus_e := new(e.G1)
	A_prim_minus_e.ScalarMult(minus_e, A_prim)
	B_prim.Add(B_prim, A_prim_minus_e)
	C_rev, _ := utils.ComputeCommitment(revealedAttributes, []e.G1{*G1}, G1) // reuse G1 for simplicity
	hiddenH1Exp, _ := utils.ComputeH1Exp([]e.G1{*G1}, v_i)

	// Compute U = C_rev^v_r * A_prim^v_e * hiddenH1Exp
	C_rev_exp := new(e.G1)
	C_rev_exp.ScalarMult(v_r, C_rev)
	A_prim_exp := new(e.G1)
	A_prim_exp.ScalarMult(v_e, A_prim)
	U := new(e.G1)
	U.Add(C_rev_exp, A_prim_exp)
	U.Add(U, hiddenH1Exp)

	// Compute real challenge
	ch, err := utils.ComputeChallenge(nonce, U, A_prim, B_prim, revealedAttributes)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Compute z values
	z_r := new(e.Scalar)
	z_r.Mul(&ch, r)
	z_r.Add(z_r, v_r)
	z_e := new(e.Scalar)
	z_e.Mul(&ch, elem)
	z_e.Neg()
	z_e.Add(z_e, v_e)
	z_i := make([]e.Scalar, len(hiddenAttributes))
	for i := 0; i < len(hiddenAttributes); i++ {
		z_i[i].Mul(&ch, r)
		aScalar := new(e.Scalar)
        aScalar.SetBytes(utils.SerializeString(hiddenAttributes[i]))
		z_i[i].Mul(&z_i[i], aScalar)
		z_i[i].Add(&z_i[i], &v_i[i])
	}

	// Prepare proof
	proof := models.SignatureProof{
		A_prim: A_prim,
		B_prim: B_prim,
		Z_e:    z_e,
		Z_r:    z_r,
		Z_i:    z_i,
		Ch:     &ch,
	}

	// Public params and key
	publicParams := models.PublicParameters{
		G1: G1,
		G2: G2,
		H1: []e.G1{*G1, *G1},
	}

	x_2 := new(e.G2)
	x_2.ScalarMult(x, G2)
	publicKey := models.PublicKey{
		X2: x_2,
	}

	// Run verify
	valid, err := verify.Verify(proof, nonce, revealedAttributes, revealedIndices, publicParams, publicKey)
	if err != nil {
		t.Fatalf("Expected valid proof but got error: %v", err)
	}
	if !valid {
		t.Fatalf("Expected proof to verify but it failed")
	}
}
