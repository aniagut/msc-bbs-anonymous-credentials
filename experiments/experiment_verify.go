package experiments

import (
	"fmt"
	"time"
	"os"
	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	"github.com/aniagut/msc-bbs-anonymous-credentials/issue"
	"github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
	"github.com/aniagut/msc-bbs-anonymous-credentials/verify"
)

// MeasureVerifyTime measures the time taken to run the Verify function for different sizes of the attributes vector
// and numbers of revealed attributes.
func MeasureVerifyTime() {
	// Define the sizes of the attributes vector to test
	lSizes := []int{20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}
	// Iterate over each size
	for _, l := range lSizes {
		// Open the results file for writing time
    	file, err := os.Create(fmt.Sprintf("experiments/results/verify_time_results_%d.txt", l))
		if err != nil {
			fmt.Printf("Error creating results file: %v\n", err)
			return
		}
		defer file.Close()

		// Write the header to the file
		_, err = file.WriteString("RevealedAttributesLength,AverageVerifyTime\n")
		if err != nil {
			fmt.Printf("Error writing to results file: %v\n", err)
			return
		}

		// Define how many attributes to reveal for each test - it needs to be at least 1 and at most l
		revealedSizes := []int{l/20, l/10, l/5, l/2, l-1, l}
		
		// Generate a list of attributes
		attributes := make([]string, l)
		for i := 0; i < l; i++ {
			attributes[i] = fmt.Sprintf("attribute%d", i+1)
		}
		// Generate public parameters, public key and secret key
		setupResult, err := setup.Setup(l)
		if err != nil {
			fmt.Printf("Error during Setup for l=%d: %v\n", l, err)
			return
		}
		publicParams := setupResult.PublicParameters
		secretKey := setupResult.SecretKey
		publicKey := setupResult.PublicKey
		
		// Generate a signature
		signature, err := issue.Issue(attributes, publicParams, secretKey)
		if err != nil {
			fmt.Printf("Error during Issue for l=%d: %v\n", l, err)
			return
		}

		for _, revealedSize := range revealedSizes {
			// Generate a list of revealed attributes and their indices
			revealed := make([]string, revealedSize)
			revealedIndices := make([]int, revealedSize)
			for i := 0; i < revealedSize; i++ {
				revealed[i] = attributes[i]
				revealedIndices[i] = i
			}
			// Generate a random nonce
			nonce := []byte("random_nonce")

			// Generate a proof
			proof, err := presentation.Presentation(attributes, signature, revealedIndices, publicParams, nonce)
			if err != nil {
				fmt.Printf("Error during Presentation for l=%d: %v\n", l, err)
				return
			}
			
			var totalTime time.Duration

			// Run Verify 10 times and measure the total time
			for i := 0; i < 10; i++ {
				start := time.Now()
				// Call Verify
				verified, err := verify.Verify(proof, nonce, revealed, revealedIndices, publicParams, publicKey)
				if err != nil {
					fmt.Printf("Error during Verify for l=%d: %v\n", l, err)
					return
				}
				// Measure the elapsed time
				elapsed := time.Since(start)
				totalTime += elapsed

				// Check if the proof is valid
				if !verified {
					fmt.Printf("Verification failed for l=%d\n", l)
					return
				}
			}
			// Calculate the average time
			averageTime := totalTime / 10
			// Print the results
			fmt.Printf("Average Verify time for l=%d with revealed size %d: %v\n", l, revealedSize, averageTime)
			// Write the results to the file
			_, err = file.WriteString(fmt.Sprintf("%d,%v\n", revealedSize, averageTime))
			if err != nil {
				fmt.Printf("Error writing to results file: %v\n", err)
				return
			}
		}
	}
}