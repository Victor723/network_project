package auditor

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"
	// "web_cert_reporting/client"
)

type Client struct {
	ID             int
	PrivateKey     *ecdh.PrivateKey
	ReportingValue []byte
	Curve          ecdh.Curve
}

// h = g^x where x is the private key
type ReportingEntry struct {
	Cert_times_h_r10 []byte
	G_ri0            []byte
	H_r_i1           []byte
	G_ri1            []byte
	Shufflers        [][]byte
}

type Database struct {
	Entries        []ReportingEntry
	Shufflers_info []ShuffleRecords
}

type ShuffleRecords struct {
	ID int
	g  []byte
	h  []byte
}

type Auditor struct {
	FileName string
	Curve    ecdh.Curve
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string, c ecdh.Curve) *Auditor {
	return &Auditor{FileName: fileName, Curve: c}
}

func (a *Auditor) InitializeDatabase() error {
	// Check if the file already exists.
	_, err := os.Stat(a.FileName)

	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.FileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.FileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.FileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.FileName)
	} else {
		return err
	}

	return nil
}

func ReadDatabase(certauditor *Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.FileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func ReportPhase_AppendEntryToDatabase(certauditor *Auditor, entry *ReportingEntry) error {
	// Read the existing data from the database file
	existingData, err := ReadDatabase(certauditor)
	if err != nil {
		return err
	}

	// Unmarshal the existing data into a slice of CipherText
	var databaseCiphertexts Database
	if len(existingData) > 0 {
		err = json.Unmarshal(existingData, &databaseCiphertexts)
		if err != nil {
			return err
		}
	} else {
		databaseCiphertexts = Database{
			Entries:        []ReportingEntry{},
			Shufflers_info: []ShuffleRecords{},
		}
	}

	// Append the new ciphertexts to the existing array
	databaseCiphertexts.Entries = append(databaseCiphertexts.Entries, *entry)
	// fmt.Println(databaseCiphertexts)
	// fmt.Println(entry)

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(databaseCiphertexts)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.FileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}
