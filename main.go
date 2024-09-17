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

// checkCNAMERecords takes a list of subdomains and returns a map where the keys are subdomain names
// and the values are structs containing CNAME records and DNS status information.
func checkCNAMERecords(subdomains []string) (map[string]Record, error) {
	results := make(map[string]Record)

	for _, subdomain := range subdomains {
		record, err := getCNAMERecord(subdomain)
		if err != nil {
			return nil, err
		}
		results[subdomain] = record
	}

	return results, nil
}

// Record holds the details for each DNS query, including CNAME record and DNS status.
type Record struct {
	CNAME  string
	Status string
	Detail string
}

// getCNAMERecord performs the dig command to get the CNAME record for a single subdomain.
func getCNAMERecord(subdomain string) (Record, error) {
	cmd := exec.Command("dig", "+short", "CNAME", subdomain)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return Record{}, fmt.Errorf("error executing dig command for %s: %v", subdomain, err)
	}

	output := strings.TrimSpace(out.String())
	stderrOutput := stderr.String()

	// Check if stderr contains NXDOMAIN
	if strings.Contains(stderrOutput, "status: NXDOMAIN") {
		return Record{
			CNAME:  "",
			Status: "NXDOMAIN",
			Detail: "Status: NXDOMAIN",
		}, nil
	}

	// Check for CNAME records
	if output == "" {
		return Record{
			CNAME:  "",
			Status: "NO CNAME",
			Detail: "Status: noerror",
		}, nil
	}

	return Record{
		CNAME:  output,
		Status: "CNAME FOUND",
		Detail: "Status: noerror",
	}, nil
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
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <subdomains-file>", os.Args[0])
	}

	filename := os.Args[1]

	// Read subdomains from the file
	subdomains, err := readSubdomainsFromFile(filename)
	if err != nil {
		log.Fatalf("Failed to read subdomains from file: %v", err)
	}

	// Check CNAME records for the subdomains
	results, err := checkCNAMERecords(subdomains)
	if err != nil {
		log.Fatalf("Failed to check CNAME records: %v", err)
	}

	// Output the results
	for subdomain, record := range results {
		fmt.Printf("Subdomain: %s, CNAME: %s, STATUS: %s, Detail: %s\n", subdomain, record.CNAME, record.Status, record.Detail)
	}
}
