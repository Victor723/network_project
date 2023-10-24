package main

import (
	"crypto/ecdh"
	"fmt"
	"web_cert_reporting/auditor"
	"web_cert_reporting/client"
)

func main() {
	// general init
	curve := ecdh.P256()
	database_name := "database.json"
	numClients := 5
	CertAuditor := auditor.NewAuditor(database_name, curve)
	// CertAuditor.InitializeDatabase()
	// fmt.Println("Auditer Initialized, Enter reporting phase")
	// /// init client and starting the reporting phase
	clients := make([]*auditor.Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = client.NewClient(CertAuditor, i)
		entry, err := client.CreateInitialEntry(clients[i])
		// fmt.Println(entry)
		if err != nil {
			fmt.Println(err)
			return
		}
		auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry)
	}
	fmt.Println("Reporting phase complete, Enter shuffling phase")
	//shuffling stage
	for i := 0; i < numClients; i++ {
		client.ClientShuffle(CertAuditor, clients[0])
	}
	fmt.Println("Shuffling Complete, Enter Reveal Phase")
	// for i := 0; i < numClients; i++ {
	// 	// client.ClientShuffle(CertAuditor, clients[i])
	// }

}
