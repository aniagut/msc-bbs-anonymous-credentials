package main

import (
	// "fmt"
	// "log"
	// "github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	// "github.com/aniagut/msc-bbs-anonymous-credentials/issue"
	// "github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
	// "github.com/aniagut/msc-bbs-anonymous-credentials/verify"
	"github.com/aniagut/msc-bbs-anonymous-credentials/experiments"
)

func main() {
	// Run the setup time measurement experiment
	experiments.MeasurePresentationTime()

	// // Example usage of the setup function
	// l := 5 // Number of independent generators
	// result, err := setup.Setup(l)
	// if err != nil {
	// 	log.Fatalf("Error during setup: %v", err)
	// }

	// fmt.Printf("Setup completed successfully!\n")
	// // fmt.Printf("Public Parameters: %+v\n", result.PublicParameters)
	// // fmt.Printf("Public Key: %+v\n", result.PublicKey)
	// // fmt.Printf("Secret Key: %+v\n", result.SecretKey)

	// // Example usage of the issue function
	// attributes := []string{"attribute1", "attribute2", "attribute3", "attribute4", "attribute5"}
	// signature, err := issue.Issue(attributes, result.PublicParameters, result.SecretKey)
	// if err != nil {
	// 	log.Fatalf("Error during issuing credential: %v", err)
	// }
	// fmt.Printf("Credential issued successfully!\n")
	// // fmt.Printf("Signature: %+v\n", signature)

	// // Example usage of the presentation function
	// revealed := []int{0, 2} // Indices of revealed attributes
	// nonce := []byte("random_nonce") // Random nonce
	// proof, err := presentation.Presentation(attributes, signature, revealed, result.PublicParameters, nonce)
	// if err != nil {
	// 	log.Fatalf("Error during presentation: %v", err)
	// }
	// fmt.Printf("Presentation completed successfully!\n")
	// // fmt.Printf("Proof: %+v\n", proof)

	// // Example usage of the verify function
	// revealedAttributes := []string{"attribute1", "attribute3"}
	// isValid, err := verify.Verify(proof, nonce, revealedAttributes, revealed, result.PublicParameters, result.PublicKey)
	// if err != nil {
	// 	log.Fatalf("Error during verification: %v", err)
	// }
	// fmt.Printf("Verification completed successfully!\n")
	// fmt.Printf("Is the proof valid? %v\n", isValid)
}