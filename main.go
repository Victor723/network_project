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
	CertAuditor.InitializeDatabase()

	/// init client and starting the reporting phase
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

	// ///shuffling stage
	// for i := 0; i < numClients; i++ {
	// 	client.ClientShuffle(CertAuditor, clients[i])
	// }

}
