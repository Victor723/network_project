package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
)

func isZero(bigInt *big.Int) bool {
	return bigInt.Sign() == 0
}

func Encrypt(shared_secret []byte, msg []byte) ([]byte, error) {
	shared_secret_int := new(big.Int).SetBytes(shared_secret)
	msg_int := new(big.Int).SetBytes(msg)
	if isZero(msg_int) {
		return nil, errors.New("message can not be zero")
	}
	return shared_secret_int.Mul(shared_secret_int, msg_int).Bytes(), nil
}

func Decrypt(shared_secret []byte, cyphertext []byte) ([]byte, error) {
	cyphertext_int := new(big.Int).SetBytes(cyphertext)
	shared_secret_int := new(big.Int).SetBytes(shared_secret)
	return shared_secret_int.Div(cyphertext_int, shared_secret_int).Bytes(), nil
}

// randBigInt generates a random big.Int of the given bit size
func randBigInt(bits int) (*big.Int, error) {
	bigInt := new(big.Int)
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits)) // 2^bits
	randBigInt, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	bigInt.Set(randBigInt)
	return bigInt, nil
}

func generate_msg_bytes() []byte {
	randomBigInt, err := randBigInt(2048)
	if err != nil {
		panic(err)
	}
	return randomBigInt.Bytes()
}

func generate_one_bytes() []byte {
	return big.NewInt(1).Bytes()
}

// ///////////////////////////////// framework

type Auditor struct {
	FileName string
}

type Client struct {
	PrivateKey ecdh.PrivateKey
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string) *Auditor {
	return &Auditor{FileName: fileName}
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

/////////////////////////////

func main() {
	curve := ecdh.P256()

	/// auditer action
	// Generate key for the auditer
	priv1, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	/// client will only use auditer's public key
	pub1 := priv1.PublicKey()
	// c1 := pub1.Bytes()

	//client action
	// Generate key for one client
	priv2, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	///generate a message, this represent a web certificate
	report_msg := generate_one_bytes()
	// report_msg := generate_msg_bytes()
	/// obtain the shared secrete
	shared_key_cli, err := priv2.ECDH(pub1)
	if err != nil {
		panic(err)
	}

	//// generate a cypher text, c2
	cyphertext, err := Encrypt(shared_key_cli, report_msg)
	if err != nil {
		panic(err)
	}
	/// pub2 is client c1
	pub2 := priv2.PublicKey()
	/////client action end, the auditor gets the cyphertext and c1

	shared_key1, err := priv1.ECDH(pub2)
	if err != nil {
		panic(err)
	}
	plaintext, err := Decrypt(shared_key1, cyphertext)

	for _, b := range cyphertext {
		fmt.Printf("%x ", b)
	}

	// fmt.Println()
	// for _, b := range report_msg {
	// 	fmt.Printf("%x ", b)
	// }

	// fmt.Println()
	// for _, b := range plaintext {
	// 	fmt.Printf("%x ", b)
	// }
	fmt.Println()
	if string(report_msg) == string(plaintext) {
		fmt.Println("Decryption successful!")
	} else {
		fmt.Println("Decryption failed!")
	}

}
