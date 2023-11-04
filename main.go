package main

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"time"
	"web_cert_reporting/aes"
	"web_cert_reporting/auditor"
	"web_cert_reporting/client"
)

func main() {
	// general init
	curve := ecdh.P256()
	database_name := "database.json"
	numClients := 10
	CertAuditor := auditor.NewAuditor(database_name, curve)
	CertAuditor.InitializeDatabase()
	fmt.Println("Auditer Initialized, Enter reporting phase")
	/// init client and starting the reporting phase
	clients := make([]*auditor.Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = client.NewClient(CertAuditor, i)
		entry, err := client.CreateInitialEntry(clients[i])
		if err != nil {
			fmt.Println(err)
			return
		}
		auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry)
	}
	fmt.Println("Reporting phase complete, Enter shuffling phase")
	//shuffling stage
	for i := 0; i < numClients; i++ {
		start := time.Now() // Start the timer
		client.ClientShuffle(CertAuditor, clients[i])
		elapsed := time.Since(start) // Calculate elapsed time
		fmt.Printf("Sequential Shuffling took %v to execute.\n", elapsed)
	}
	fmt.Println("Shuffling Complete, Enter Reveal Client Phase")
	for i := 0; i < numClients; i++ {
		db := client.ClientReveal(CertAuditor, clients[i])
		err := auditor.WriteRevealInfoToDatabase(CertAuditor, db)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	fmt.Println("Client Reveal Complete, Auditor Calculating the entries")
	result := auditor.CalculateEntries(CertAuditor)
	successful := true
	fmt.Println("Results calculated, verifying the correctness of the entries")
	for i := 0; i < numClients; i++ {
		fmt.Print("checking for client ")
		fmt.Print(clients[i].ID)
		fmt.Println(": ")
		// fmt.Print("Intended Reporting value is")
		// fmt.Println(clients[i].ReportingValue)
		// fmt.Println("Finding the entry in the auditor logs")
		successful_one_client := false
		for j := 0; j < len(result); j++ {
			if bytes.Equal(result[j], clients[i].ReportingValue) {
				fmt.Print("Found Matching Entry! At index ")
				fmt.Println(j)
				successful_one_client = true
			}
		}
		if !successful_one_client {
			successful = false
		}
	}
	if successful {
		fmt.Println("Success! Every Clients' entries are reported and decrypted correctly")
	} else {
		fmt.Println("FAIL!")

	}

	// AES encrypt and decrypt
	key := []byte("a very strongkey") // 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
	plainText := []byte("Hello, World!")

	encryptedData, err := aes.Encrypt(plainText, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted: %x\n", encryptedData)

	decryptedData, err := aes.Decrypt(encryptedData, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted: %s\n", decryptedData)

}
