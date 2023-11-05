package main

// the types in this code need refactoring
import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
	"web_cert_reporting/auditor"
	"web_cert_reporting/client"
)

func main() {
	// general init
	curve := ecdh.P256()
	database_name := "database.json"
	numClients := 5
	secret_pieces := numClients - 1
	threshold := 4
	clients_sit_out := 1
	CertAuditor := auditor.NewAuditor(database_name, curve)
	CertAuditor.InitializeDatabase()
	fmt.Println("Auditer Initialized, Enter reporting phase")
	/// init client and starting the reporting phase
	clients := make([]*auditor.Client, numClients)
	clients_out := make([]*auditor.Client, clients_sit_out)
	for i := 0; i < numClients; i++ {
		clients[i] = client.NewClient(CertAuditor, i)
		// register shuffling key to the auditor
		client.RegisterShuffleKeyWithAduitor(clients[i], CertAuditor)
	}
	// shuffle client order to make sure that the protocol works
	ShuffleClient(clients)

	for i := 0; i < numClients; i++ {
		entry, err := client.CreateInitialEntry(clients[i])
		if err != nil {
			fmt.Println(err)
			return
		}
		auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry)
		//// client shares the secrete in a encrypted way
		client.SecreteShare(CertAuditor, clients[i], secret_pieces, threshold)
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
	fmt.Println("Making a copy of the shuffled database")
	auditor.MakeACopyOfDatabase(CertAuditor)
	fmt.Println("Done!")
	fmt.Println("Fault Tolerant, Randomly picking clients that will not participate")
	for i := 0; i < clients_sit_out; i++ {
		// picking clients to sit out
		clients_out[i], clients = removeRandomElement(clients)
	}

	for i := 0; i < len(clients); i++ {
		db := client.ClientReveal(CertAuditor, clients[i])
		err := auditor.WriteRevealInfoToDatabase(CertAuditor, db)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	fmt.Println("Client Reveal Complete, Auditor Calculating the entries")
	result := auditor.CalculateEntries(CertAuditor)

	if clients_sit_out > 0 {
		// fault tolerance kick in
		fmt.Println("Fault Tolerant Kicking in")
		for i := 0; i < len(clients_out); i++ {
			fault_tolerant_results := []*auditor.SecreteShareDecrypt{}
			// client reports the pieces to the auditor to decrypt
			for j := 0; j < len(clients); j++ {
				decrypted_piece, err := client.ClientReportDecryptedSecret(CertAuditor, clients[j], clients_out[i].ID)
				if err != nil && decrypted_piece != nil {
					fault_tolerant_results = append(fault_tolerant_results, decrypted_piece)
				}
			}
			/// may need to check whether the client number required passed the threshold
			// compute the new result after this round of fault tolerance
			// var err error
			// result, err = auditor.CalculateEntriesForFaultToleranceOfOneClient(CertAuditor, result, fault_tolerant_results)
			// if err != nil {
			// 	fmt.Println(err)
			// 	return
			// }
		}
	}
	successful := true
	fmt.Println("Results calculated, verifying the correctness of the entries")
	for i := 0; i < len(clients); i++ {
		fmt.Print("checking for client ")
		fmt.Print(clients[i].ID)
		fmt.Println(": ")
		// fmt.Print("Intended Reporting value is")
		// fmt.Println(clients[i].ReportingValue)
		fmt.Println("Finding the entry in the auditor logs")
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
	fmt.Println("This is Fault Tolerant Version!")
}

func removeRandomElement(slice []*auditor.Client) (*auditor.Client, []*auditor.Client) {
	index := rand.Intn(len(slice))
	removed := slice[index]
	return removed, append(slice[:index], slice[index+1:]...)
}

func ShuffleClient(slice []*auditor.Client) {
	n := len(slice)
	for i := n - 1; i > 0; i-- {
		j := randomInt(i + 1)                   // Get a secure random index from 0 to i
		slice[i], slice[j] = slice[j], slice[i] // Swap the elements at indexes i and j
	}
}

// randomInt returns a secure random integer between 0 (inclusive) and n (exclusive).
func randomInt(n int) int {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}
