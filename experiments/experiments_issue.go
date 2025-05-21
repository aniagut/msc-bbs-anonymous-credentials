package experiments

import (
	"fmt"
	"time"
	"os"
	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	"github.com/aniagut/msc-bbs-anonymous-credentials/issue"
)


func MeasureIssueTime() {
	// Open the results file for writing
    file, err := os.Create("experiments/results/issue_time_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()

	// Write the header to the file
    _, err = file.WriteString("AttributesVectorLength,AverageIssueTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }

	// Define the sizes of the attributes vector to test
	lSizes := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}
	// Iterate over each size
	for _, l := range lSizes {
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

		var totalTime time.Duration
		// Run Issue 10 times and measure the total time
		for i := 0; i < 10; i++ {
			start := time.Now()
			// Call Issue
			_, err := issue.Issue(attributes, publicParams, secretKey)
			if err != nil {
				fmt.Printf("Error during Issue for l=%d: %v\n", l, err)
				return
			}
			// Measure the elapsed time
			elapsed := time.Since(start)
			totalTime += elapsed
		}
		// Calculate the average time
		averageTime := totalTime / 10
		// Print the results
		fmt.Printf("Average Issue time for l=%d: %v\n", l, averageTime)

		// Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", l, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
	}
}