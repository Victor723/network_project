package main

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"time"

	"web_cert_reporting/aes"
	"web_cert_reporting/auditor"
	"web_cert_reporting/client"
	"web_cert_reporting/elgamal"
	"web_cert_reporting/shamir"
)

func main() {
	// // general init
	curve := ecdh.P256()
	database_name := "database.json"
	numClients := 10
	CertAuditor := auditor.NewAuditor(database_name, curve)
	CertAuditor.InitializeDatabase()
	fmt.Println("Auditer Initialized, Enter reporting phase")
	// / init client and starting the reporting phase
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
	pri_key := clients[0].PrivateKey.Bytes() // get some key
	fmt.Println("client key: ", pri_key)

	parts, err := shamir.Split(pri_key, 10, 7)
	if err != nil {
		fmt.Println(err)
		return
	}

	var pri_part []byte
	var tag byte
	for k, v := range parts {
		pri_part = v
		tag = k
		break
	}
	fmt.Println("tag: ", tag)
	fmt.Println("splitted_part: ", pri_part)

	a := elgamal.Generate_Random_Dice_point(curve)
	key := aes.DeriveKeyFromSHA256([]byte(a), 16) // 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256

	encryptedData, err := aes.Encrypt(pri_part, key) //encrypt
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted: ", encryptedData)

	decryptedData, err := aes.Decrypt(encryptedData, key) //decrypt
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted: ", decryptedData)

	if bytes.Equal(pri_part, decryptedData) { // compare equal
		fmt.Println("The slices are equal.")
	} else {
		fmt.Println("The slices are not equal.")
	}

}
