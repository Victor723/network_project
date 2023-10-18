package client

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
)

type Client struct {
	PrivateKey ecdh.PrivateKey
}

func ReadDatabase(fileName string) ([]byte, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func AppendCiphertextToDatabase(fileName string, ciphertexts []*CipherText) error {
	// Read the existing data from the database file
	existingData, err := ReadDatabase(fileName)
	if err != nil {
		return err
	}

	// Unmarshal the existing data into a slice of CipherText
	var databaseCiphertexts []*CipherText
	if len(existingData) > 0 {
		err = json.Unmarshal(existingData, &databaseCiphertexts)
		if err != nil {
			return err
		}
	}

	// Append the new ciphertexts to the existing array
	databaseCiphertexts = append(databaseCiphertexts, ciphertexts...)

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(databaseCiphertexts)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(fileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}
