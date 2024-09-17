package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Record holds the details for each DNS query, including CNAME record and vulnerability status.
type Record struct {
	CNAME       string
	IsVulnerable bool
}

// checkCNAMERecords takes a list of subdomains and patterns, and returns a map where the keys are subdomain names
// and the values are Records containing CNAME records and whether they are vulnerable based on wildcard domain matching.
func checkCNAMERecords(subdomains []string, patterns []string) (map[string]Record, error) {
	results := make(map[string]Record)

	for _, subdomain := range subdomains {
		cname, err := getCNAMERecord(subdomain)
		if err != nil {
			return nil, err
		}

		wildcardDomain := extractWildcardDomain(cname)
		isVulnerable := matchesAnyPattern(wildcardDomain, patterns)

		results[subdomain] = Record{
			CNAME:       cname,
			IsVulnerable: isVulnerable,
		}
	}

	return results, nil
}

// getCNAMERecord performs the dig command to get the CNAME record for a single subdomain.
func getCNAMERecord(subdomain string) (string, error) {
	cmd := exec.Command("dig", "+short", "CNAME", subdomain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing dig command for %s: %v", subdomain, err)
	}

	cname := strings.TrimSpace(out.String())
	if cname == "" {
		return "No CNAME record", nil
	}

	return cname, nil
}

// extractWildcardDomain filters out only the wildcard domains from the CNAME record.
func extractWildcardDomain(cname string) string {
	if cname == "No CNAME record" {
		return ""
	}

	// Remove the leading '*' if present
	cname = strings.TrimSpace(cname)
	if strings.HasPrefix(cname, "*.") {
		cname = cname[2:] // Remove the "*." from the start
	}

	return cname
}

// matchesAnyPattern checks if the domain matches any of the given patterns.
func matchesAnyPattern(domain string, patterns []string) bool {
	if domain == "" {
		return false
	}
	for _, pattern := range patterns {
		if strings.Contains(domain, pattern) {
			return true
		}
	}
	return false
}

// readLinesFromFile reads lines from a text file and returns them as a slice of strings.
func readLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %v", filename, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	return lines, nil
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <subdomains-file> <patterns-file> <result-file>", os.Args[0])
	}

	subdomainsFile := os.Args[1]
	patternsFile := os.Args[2]
	resultFile := os.Args[3]

	// Read subdomains and patterns from the respective files
	subdomains, err := readLinesFromFile(subdomainsFile)
	if err != nil {
		log.Fatalf("Failed to read subdomains from file: %v", err)
	}

	patterns, err := readLinesFromFile(patternsFile)
	if err != nil {
		log.Fatalf("Failed to read patterns from file: %v", err)
	}

	// Check CNAME records for the subdomains with the given patterns
	results, err := checkCNAMERecords(subdomains, patterns)
	if err != nil {
		log.Fatalf("Failed to check CNAME records: %v", err)
	}

	// Write the results to the result file, only those marked as vulnerable
	file, err := os.Create(resultFile)
	if err != nil {
		log.Fatalf("Failed to create result file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for subdomain, record := range results {
		if record.IsVulnerable {
			_, err := fmt.Fprintf(writer, "Subdomain: %s, CNAME: %s, Vulnerable: Yes\n", subdomain, record.CNAME)
			if err != nil {
				log.Fatalf("Failed to write to result file: %v", err)
			}
		}
	}

	writer.Flush()
}
