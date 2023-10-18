package main

import (
	"crypto/ecdh"
	"web_cert_reporting/auditor"
	"web_cert_reporting/client"
)

func main() {
	curve := ecdh.P256()
	database_name := "database.txt"
	numClients := 5
	CertAuditor := auditor.NewAuditor(database_name, curve)
	CertAuditor.InitializeDatabase()
	clients := make([]*auditor.Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = client.NewClient(CertAuditor, i)
		entry, err := client.CreateInitialEntry(clients[i])
		if err != nil {
			return
		}
		auditor.AppendEntryToDatabase(CertAuditor, entry)
	}
}
