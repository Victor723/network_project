package auditor

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"web_cert_reporting/elgamal"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type Client struct {
	ID             int
	ReportingKey   *ecdh.PrivateKey
	ShuffleKey     *ecdh.PrivateKey
	ReportingValue []byte
	Curve          ecdh.Curve
	G_report       []byte /// init point needs to be different for every client
	H_report       []byte
	G_shuffle      []byte /// init point needs to be different for every client
	H_shuffle      []byte
	DH_Pub_H       []byte /// pub key for secrete sharing
	DH_Pub_private []byte
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
	Entries         []*ReportingEntry
	Shufflers_info  []*ShuffleRecords
	Decrypt_info    []*DecryptRecords
	Shuffle_PubKeys []*ShufflePubKeys
	SecreteShareMap map[int][]*SecreteSharePoint
}

type ShuffleRecords struct {
	ID int
	// H_i []byte
	// G_i []byte
}

type SecreteSharePoint struct {
	Intended_Client int
	Tag             uint32
	Encrypted_y     []byte
}

type ShufflePubKeys struct {
	ID       int
	H_i      []byte
	G_i      []byte
	DH_Pub_H []byte
}

type DecryptRecords struct {
	ShufflerID int
	Keys       [][]byte
}

type Auditor struct {
	FileName         string
	Curve            ecdh.Curve
	Shamir_pieces    uint32
	Shamir_threshold uint32
	Shamir_curve     *curves.Curve
}

type SecreteShareDecrypt struct {
	Tag           uint32
	DecryptPieces [][]byte
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string, c ecdh.Curve, shamir_p uint32, shamir_t uint32, shamir_curve *curves.Curve) *Auditor {
	return &Auditor{FileName: fileName, Curve: c, Shamir_pieces: shamir_p, Shamir_threshold: shamir_t, Shamir_curve: shamir_curve}
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

	data, err := ReadDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var database Database
	if len(data) > 0 {
		err = json.Unmarshal(data, &database)
		if err != nil {
			return err
		}
	} else {
		database = Database{
			Entries:         []*ReportingEntry{},
			Shufflers_info:  []*ShuffleRecords{},
			Decrypt_info:    []*DecryptRecords{},
			Shuffle_PubKeys: []*ShufflePubKeys{},
			SecreteShareMap: make(map[int][]*SecreteSharePoint),
		}
	}

	WriteRevealInfoToDatabase(a, &database)

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
	err = json.Unmarshal(existingData, &databaseCiphertexts)
	if err != nil {
		return err
	}

	// Append the new ciphertexts to the existing array
	databaseCiphertexts.Entries = append(databaseCiphertexts.Entries, entry)

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

func WriteRevealInfoToDatabase(certauditor *Auditor, db *Database) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(db)
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

func CalculateEntries(certauditor *Auditor) [][]byte {
	/// reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	res := [][]byte{}
	// decrypting
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
		for j := 0; j < len(database.Decrypt_info); j++ {
			res[i], err = elgamal.Decrypt(database.Decrypt_info[j].Keys[i], res[i])
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
		}
	}
	return res
}

// func CalculateEntries_one_client(certauditor *Auditor, client *Client, database *Database) [][]byte {

// 	res := [][]byte{}
// 	// decrypting
// 	for i := 0; i < len(database.Entries); i++ {
// 		for j := 0; j < len(database.Decrypt_info); j++ {
// 			if database.Decrypt_info[j].ShufflerID == client.ID {
// 				res = append(res, database.Decrypt_info[j].Keys[i])
// 			}
// 		}
// 	}
// 	return res
// }

func MakeACopyOfDatabase(certauditor *Auditor) error {
	// / reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile("database_copy.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalculateEntriesForFaultToleranceOfOneClient(CertAuditor *Auditor, result [][]byte, fault_tolerant_results []*SecreteShareDecrypt) ([][]byte, error) {
	// the laranagian method, brutal
	// construct a map and a tag array to enable better access
	list_of_tags := make([]uint32, len(fault_tolerant_results))
	for i := 0; i < len(list_of_tags); i++ {
		// result[i]
		list_of_tags[i] = fault_tolerant_results[i].Tag
	}
	// fmt.Println(list_of_tags)
	// recreate the shamir and calculate coefficients
	scheme, _ := sharing.NewShamir(CertAuditor.Shamir_threshold, CertAuditor.Shamir_pieces, CertAuditor.Shamir_curve)
	lagrange_map, err := scheme.LagrangeCoeffs(list_of_tags)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	// apply larangian to every entry
	// fmt.Println(lagrange_map)
	/// add up first
	calculated_res := [][]byte{}
	for i := 0; i < len(fault_tolerant_results); i++ {
		// result[i]
		lcoef := lagrange_map[fault_tolerant_results[i].Tag].Bytes()
		for j := 0; j < len(result); j++ {
			d_lambda, err := elgamal.ECDH_bytes(fault_tolerant_results[i].DecryptPieces[j], lcoef)
			if err != nil {
				log.Fatalf("%v", err)
				return nil, err
			}
			if i == 0 {
				calculated_res = append(calculated_res, d_lambda)
			} else {
				calculated_res[j], err = elgamal.Encrypt(calculated_res[j], d_lambda)
				if err != nil {
					log.Fatalf("%v", err)
					return nil, err
				}
			}
		}
	}
	for k := 0; k < len(result); k++ {
		result[k], _ = elgamal.Decrypt(calculated_res[k], result[k])
	}
	return result, err
}

// func ReconstructKey(CertAuditor *Auditor, clients_out_1 *Client, fault_tolerant_results []*SecreteShareDecrypt) {
// 	var l []*sharing.ShamirShare
// 	for i := 0; i < len(fault_tolerant_results); i++ {
// 		o := &sharing.ShamirShare{
// 			Id:    fault_tolerant_results[i].Tag,
// 			Value: fault_tolerant_results[i].Decrypt_Y}
// 		l = append(l, o)
// 	}
// 	scheme, _ := sharing.NewShamir(CertAuditor.Shamir_threshold, CertAuditor.Shamir_pieces, CertAuditor.Shamir_curve)
// 	r, err := scheme.Combine(l...)
// 	fmt.Println(len(fault_tolerant_results))
// 	if err != nil {
// 		log.Fatalf("%v", err)
// 		return
// 	}

// 	fmt.Println(r)
// 	fmt.Println(clients_out_1.ShuffleKey.Bytes())
// }
