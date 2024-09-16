
package main

import (
	"bytes"
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// checkCNAMERecords takes a list of subdomains and returns a map where the keys are subdomain names
// and the values are CNAME records (if any). If a subdomain does not have a CNAME record, its value is empty.
func checkCNAMERecords(subdomains []string) (map[string]string, error) {
	results := make(map[string]string)

	for _, subdomain := range subdomains {
		cname, err := getCNAMERecord(subdomain)
		if err != nil {
			return nil, err
		}
		results[subdomain] = cname
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

// readSubdomainsFromFile reads subdomains from a text file and returns them as a slice of strings.
func readSubdomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %v", filename, err)
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	return subdomains, nil
}

func main() {
	// Read subdomains from the file
	subdomains, err := readSubdomainsFromFile("subdomains.txt")
	if err != nil {
		log.Fatalf("Failed to read subdomains from file: %v", err)
	}

	// Check CNAME records for the subdomains
	results, err := checkCNAMERecords(subdomains)
	if err != nil {
		log.Fatalf("Failed to check CNAME records: %v", err)
	}

	// Output the results
	for subdomain, cname := range results {
		fmt.Printf("Subdomain: %s, CNAME: %s\n", subdomain, cname)
	}
}
