package main

import (
	"fmt"
	"log"
	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	"github.com/aniagut/msc-bbs-anonymous-credentials/issue"
	"github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
	"github.com/aniagut/msc-bbs-anonymous-credentials/verify"
)

func main() {
	// Example usage of the setup function
	l := 5 // Number of independent generators
	result, err := setup.Setup(l)
	if err != nil {
		log.Fatalf("Error during setup: %v", err)
	}

	fmt.Printf("Setup completed successfully!\n")

	// Example usage of the issue function
	attributes := []string{"attribute1", "attribute2", "attribute3", "attribute4", "attribute5"}
	signature, err := issue.Issue(attributes, result.PublicParameters, result.SecretKey)
	if err != nil {
		log.Fatalf("Error during issuing credential: %v", err)
	}
	fmt.Printf("Credential issued successfully!\n")

	// Example usage of the presentation function
	revealed := []int{0, 4} // Indices of revealed attributes
	nonce := []byte("random_nonce") // Random nonce
	proof, err := presentation.Presentation(attributes, signature, revealed, result.PublicParameters, nonce)
	if err != nil {
		log.Fatalf("Error during presentation: %v", err)
	}
	fmt.Printf("Presentation completed successfully!\n")

	// Example usage of the verify function
	revealedAttributes := []string{"attribute1", "attribute5"}
	isValid, err := verify.Verify(proof, nonce, revealedAttributes, revealed, result.PublicParameters, result.PublicKey)
	if err != nil {
		log.Fatalf("Error during verification: %v", err)
	}
	fmt.Printf("Verification completed successfully!\n")
	fmt.Printf("Is the proof valid? %v\n", isValid)
}