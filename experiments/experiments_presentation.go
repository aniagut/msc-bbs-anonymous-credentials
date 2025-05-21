package experiments

import (
	"fmt"
	"time"
	"os"
	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	"github.com/aniagut/msc-bbs-anonymous-credentials/issue"
	"github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
	"encoding/gob"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"bytes"
)


func MeasurePresentationTime() {
	// Define the sizes of the attributes vector to test
	lSizes := []int{20, 50, 100, 200, 500, 1000, 2000, 5000}
	// Iterate over each size
	for _, l := range lSizes {
		// Open the results file for writing time
    	file, err := os.Create(fmt.Sprintf("experiments/results/presentation_time_results_%d.txt", l))
		if err != nil {
			fmt.Printf("Error creating results file: %v\n", err)
			return
		}
		defer file.Close()

		//Open the results file for writing size of presentation
		fileSize, err := os.Create(fmt.Sprintf("experiments/results/presentation_size_results_%d.txt", l))
		if err != nil {
			fmt.Printf("Error creating results file: %v\n", err)
			return
		}
		defer fileSize.Close()

		// Write the header to the file
		_, err = file.WriteString("RevealedAttributesLength,AveragePresentationTime\n")
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
		// Generate public parameters and secret key
		setupResult, err := setup.Setup(l)
		if err != nil {
			fmt.Printf("Error during Setup for l=%d: %v\n", l, err)
			return
		}
		publicParams := setupResult.PublicParameters
		secretKey := setupResult.SecretKey
		// Generate a signature
		signature, err := issue.Issue(attributes, publicParams, secretKey)
		if err != nil {
			fmt.Printf("Error during Issue for l=%d: %v\n", l, err)
			return
		}

		var totalTime time.Duration
		var totalProofSize int

		for _, revealedSize := range revealedSizes {
			// Generate a list of revealed attributes
			revealed := make([]int, revealedSize)
			for i := 0; i < revealedSize; i++ {
				revealed[i] = i
			}
			// Generate a random nonce
			nonce := []byte("random_nonce")
			// Run Presentation 10 times and measure the total time
			for i := 0; i < 10; i++ {
				start := time.Now()
				// Call Presentation
				proof, err := presentation.Presentation(attributes, signature, revealed, publicParams, nonce)
				if err != nil {
					fmt.Printf("Error during Presentation for l=%d: %v\n", l, err)
					return
				}
				// Measure the elapsed time
				elapsed := time.Since(start)
				totalTime += elapsed

				proofBytes, err := serializeToBytes(proof)
				// Check if serialization was successful
				if err != nil {
					fmt.Printf("Error serializing proof: %v\n", err)
					return
				}
				totalProofSize += len(proofBytes)
			}
			// Calculate the average time
			averageTime := totalTime / 10
			averageProofSize := totalProofSize / 10
			// Print the results
			fmt.Printf("Average Presentation time for l=%d with revealed size %d: %v\n", l, revealedSize, averageTime)
			// Write the results to the file
			_, err = file.WriteString(fmt.Sprintf("%d,%v\n", revealedSize, averageTime))
			if err != nil {
				fmt.Printf("Error writing to results file: %v\n", err)
				return
			}
			// Print the size of the proof
			fmt.Printf("Average size of the proof for l=%d with revealed size %d: %d bytes\n", l, revealedSize, averageProofSize)
			// Write the size of the proof to the file
			_, err = fileSize.WriteString(fmt.Sprintf("%d,%d\n", revealedSize, averageProofSize))
			if err != nil {
				fmt.Printf("Error writing to results file: %v\n", err)
				return
			}

		}
	}
}

func serializeToBytes(proof models.SignatureProof) ([]byte, error) {
    var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
    err := enc.Encode(proof)
    return buf.Bytes(), err
}