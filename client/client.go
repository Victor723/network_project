package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"web_cert_reporting/aes"
	"web_cert_reporting/auditor"
	"web_cert_reporting/elgamal"

	"github.com/coinbase/kryptology/pkg/sharing"
)

// NewAuditor creates a new Auditor instance
func NewClient(certauditor *auditor.Auditor, id int) *auditor.Client {
	k_report, err := certauditor.Curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	k_shuffle, err := certauditor.Curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dh_pub, err := certauditor.Curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	g_report := elgamal.Generate_Random_Dice_point(certauditor.Curve)
	h_report, err := elgamal.ECDH_bytes(g_report, k_report.Bytes())
	if err != nil {
		panic(err)
	}

	g_shuffle := elgamal.Generate_Random_Dice_point(certauditor.Curve)
	h_shuffle, err := elgamal.ECDH_bytes(g_shuffle, k_shuffle.Bytes())
	if err != nil {
		panic(err)
	}

	dh_pub_h := dh_pub.PublicKey().Bytes()
	dh_pub_pri := dh_pub.Bytes()
	//TODO map msg to a curve
	return &auditor.Client{
		ID:             id,
		ReportingKey:   k_report,
		ShuffleKey:     k_shuffle,
		ReportingValue: elgamal.Generate_msg_bytes(certauditor.Curve),
		Curve:          certauditor.Curve,
		G_report:       g_report,
		H_report:       h_report,
		G_shuffle:      g_shuffle,
		H_shuffle:      h_shuffle,
		DH_Pub_H:       dh_pub_h,
		DH_Pub_private: dh_pub_pri,
	}
}

func RegisterShuffleKeyWithAduitor(client *auditor.Client, certauditor *auditor.Auditor) error {
	// retrieve everything in the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		return err
	}
	var database auditor.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v here?", err)
		return err
	}

	client_info := &auditor.ShufflePubKeys{
		ID:       client.ID,
		H_i:      client.H_shuffle,
		G_i:      client.G_shuffle,
		DH_Pub_H: client.DH_Pub_H,
	}

	database.Shuffle_PubKeys = append(database.Shuffle_PubKeys, client_info)

	updatedData, err := json.Marshal(database)
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

func ReadDatabase(certauditor *auditor.Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.FileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func CreateInitialEntry(client *auditor.Client) (*auditor.ReportingEntry, error) {
	ri0 := elgamal.Generate_Random_Dice_seed(client.Curve)
	h_r_i0, err := elgamal.ECDH_bytes(client.H_report, ri0)
	if err != nil {
		return nil, err
	}
	/// generate the first two item
	cert_times_h_r10, err := elgamal.Encrypt(h_r_i0, client.ReportingValue)
	if err != nil {
		return nil, err
	}
	// FIXED each client should have different g
	g_r_i0, err := elgamal.ECDH_bytes(client.G_report, ri0)
	if err != nil {
		return nil, err
	}
	/// generate the second two item
	ri1 := elgamal.Generate_Random_Dice_seed(client.Curve)
	if err != nil {
		return nil, err
	}
	h_r_i1, err := elgamal.ECDH_bytes(client.H_report, ri1)
	if err != nil {
		return nil, err
	}
	g_r_i1, err := elgamal.ECDH_bytes(client.G_report, ri1)
	if err != nil {
		return nil, err
	}
	return &auditor.ReportingEntry{
		Cert_times_h_r10: cert_times_h_r10,
		G_ri0:            g_r_i0,
		H_r_i1:           h_r_i1,
		G_ri1:            g_r_i1,
		Shufflers:        [][]byte{},
	}, nil
}

func LocatePublicKeyWithID(clientID int, ShufflerPublicKeys []*auditor.ShufflePubKeys) (*auditor.ShufflePubKeys, error) {
	for i := 0; i < len(ShufflerPublicKeys); i++ {
		if clientID == ShufflerPublicKeys[i].ID {
			return ShufflerPublicKeys[i], nil
		}
	}
	return nil, errors.New("Shuffler public key not found")
}

func ClientShuffle(certauditor *auditor.Auditor, reportingClient *auditor.Client) error {
	// retrieve everything in the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		return err
	}
	var database auditor.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}
	first_shuffle := true
	if len(database.Shufflers_info) > 0 {
		// not first shuffle
		first_shuffle = false
	}
	//  TODO more robust checks needed
	// randomize the entries
	for i := 0; i < len(database.Entries); i++ {
		r_i_0_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		r_i_1_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		////////// r_i_0_prime   rolling///////
		// roll the Cert_times_h_r10 with r_i_0_prime
		rolled_H_r_i1, err := elgamal.ECDH_bytes(database.Entries[i].H_r_i1, r_i_0_prime)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		/// add the roll the Cert_times_h_r10 with r_i_0_prime in with Cert_times_h_r10
		new_Cert_times_h_r10, err := elgamal.Encrypt(rolled_H_r_i1, database.Entries[i].Cert_times_h_r10)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		database.Entries[i].Cert_times_h_r10 = new_Cert_times_h_r10
		// roll G_ri0 r_i_0_prime
		// database.Entries[i].G_ri0
		rolled_with_G_ri1, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, r_i_0_prime)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		//add in the G_ri1 rolled with r_i_0_prime into
		new_G_ri0, err := elgamal.Encrypt(rolled_with_G_ri1, database.Entries[i].G_ri0)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		database.Entries[i].G_ri0 = new_G_ri0
		////////// r_i_1_prime   rolling///////
		// roll the H_r_i1 with r_i_1_prime
		rolled_H_ri1_ri_1_prime, err := elgamal.ECDH_bytes(database.Entries[i].H_r_i1, r_i_1_prime)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		database.Entries[i].H_r_i1 = rolled_H_ri1_ri_1_prime
		// roll the g_r_i1 with r_i_1_prime
		rolled_g_ri1_ri_1_prime, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, r_i_1_prime)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		database.Entries[i].G_ri1 = rolled_g_ri1_ri_1_prime
		// encrypt and append g_r_i_k
		r_i_k := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		g_r_i_k, err := elgamal.Convert_seed_To_point(r_i_k, reportingClient.Curve)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		// append the g_r_i_k to the entry shufflers
		database.Entries[i].Shufflers = append(database.Entries[i].Shufflers, g_r_i_k)
		shared_h_r_i_k, err := elgamal.ECDH_bytes(g_r_i_k, reportingClient.ShuffleKey.Bytes())
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		/// encrypt the entry again with the shared key
		database.Entries[i].Cert_times_h_r10, err = elgamal.Encrypt(shared_h_r_i_k, database.Entries[i].Cert_times_h_r10)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		if !first_shuffle {
			/// not the first shuffle, re-randomize the previous shufflers
			for i := 0; i < len(database.Entries[i].Shufflers)-1; i++ {
				shuffler_info := database.Shufflers_info[i]
				keys, err := LocatePublicKeyWithID(shuffler_info.ID, database.Shuffle_PubKeys)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				r_i_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
				g_r_i_prime, err := elgamal.ECDH_bytes(keys.G_i, r_i_prime)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				/// changing the shuffler entry
				order, err := LocateShuffleOrderWithID(shuffler_info.ID, database.Shufflers_info)
				if err != nil {
					log.Fatalf("%v", err)
					return nil
				}
				database.Entries[i].Shufflers[order], err = elgamal.Encrypt(database.Entries[i].Shufflers[order], g_r_i_prime)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				/// changing the msg entry
				h_r_i_prime, err := elgamal.ECDH_bytes(keys.H_i, r_i_prime)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				database.Entries[i].Cert_times_h_r10, err = elgamal.Encrypt(h_r_i_prime, database.Entries[i].Cert_times_h_r10)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
			}
		}
	}
	/// append the client info
	client_info := &auditor.ShuffleRecords{
		ID: reportingClient.ID,
		// H_i: reportingClient.H_shuffle,
		// G_i: reportingClient.G_shuffle,
	}

	database.Shufflers_info = append(database.Shufflers_info, client_info)
	fmt.Print(reportingClient.ID)
	fmt.Println(" shuffling")
	ShuffleEntries(database.Entries)
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
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

// Shuffle securely shuffles the order of the input slice.
func ShuffleEntries(slice []*auditor.ReportingEntry) {
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

func LocateShuffleOrderWithID(clientID int, Shufflers []*auditor.ShuffleRecords) (int, error) {
	for i := 0; i < len(Shufflers); i++ {
		if clientID == Shufflers[i].ID {
			return i, nil
		}
	}
	return -1, errors.New("Shuffle order not found")
}

func ClientReveal(certauditor *auditor.Auditor, revealingClient *auditor.Client) *auditor.Database {
	// retrieve everything in the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database auditor.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	/// loop to provide info
	revealRecords := &auditor.DecryptRecords{
		ShufflerID: revealingClient.ID,
		Keys:       [][]byte{},
	}

	order, err := LocateShuffleOrderWithID(revealingClient.ID, database.Shufflers_info)
	if err != nil {
		log.Fatalf("%v", err)
		return nil
	}
	for i := 0; i < len(database.Entries); i++ {
		// check if this is my entry
		h_test, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, revealingClient.ReportingKey.Bytes())
		if err != nil {
			log.Fatalf("%v", err)
			return nil
		}

		if bytes.Equal(h_test, database.Entries[i].H_r_i1) {
			// it is my entry
			fmt.Print(revealingClient.ID)
			fmt.Println(" found entry")

			g_first_term_with_shuffle_key, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[order], revealingClient.ShuffleKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}

			g_second_term_with_reporting_key, err := elgamal.ECDH_bytes(database.Entries[i].G_ri0, revealingClient.ReportingKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
			reveal_value_self, err := elgamal.Encrypt(g_first_term_with_shuffle_key, g_second_term_with_reporting_key)

			revealRecords.Keys = append(revealRecords.Keys, reveal_value_self)
		} else {
			// it is not
			reveal_value_non_self, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[order], revealingClient.ShuffleKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
			revealRecords.Keys = append(revealRecords.Keys, reveal_value_non_self)
		}

	}
	database.Decrypt_info = append(database.Decrypt_info, revealRecords)
	return &database
}

// /////screte sharing ///////
func SecreteShare(certauditor *auditor.Auditor, reportingClient *auditor.Client) error {
	//// read the database first
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database auditor.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	/// start secrete sharing and store it on the auditor
	// secrete pieces has to be bigger than threshold
	scheme, err := sharing.NewShamir(certauditor.Shamir_threshold, certauditor.Shamir_pieces, certauditor.Shamir_curve)
	if err != nil {
		log.Fatalf("%v", err)
		return err
	}
	key_value_scalar, err := certauditor.Shamir_curve.NewScalar().SetBytes(reportingClient.ShuffleKey.Bytes())
	if err != nil {
		log.Fatalf("%v", err)
		return err
	}
	shares, err := scheme.Split(key_value_scalar, rand.Reader)
	if err != nil {
		log.Fatalf("%v", err)
		return err
	}
	// fmt.Println(len(reportingClient.ShuffleKey.Bytes()))
	// fmt.Println(len(reportingClient.H_report))
	// database.Shuffle_PubKeys
	encrypt_secrete_array := []*auditor.SecreteSharePoint{}
	/// generate a list of client ids to randomly choose from, of course the reporting client is excluded
	list_client_id := []int{}
	for i := 0; i < len(database.Shuffle_PubKeys); i++ {
		if database.Shuffle_PubKeys[i].ID != reportingClient.ID {
			list_client_id = append(list_client_id, database.Shuffle_PubKeys[i].ID)
		}
	}
	for i := 0; i < len(shares); i++ {
		// tag: p and y: pieces[p]
		/// remove a client to have the secrete
		var removed_client int
		removed_client, list_client_id = removeRandomElement_int(list_client_id)
		intended_client_keys, err := LocatePublicKeyWithID(removed_client, database.Shuffle_PubKeys)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		intended_client_SharedSecret, err := elgamal.ECDH_bytes(intended_client_keys.DH_Pub_H, reportingClient.DH_Pub_private)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		symmetric_key := aes.DeriveKeyFromSHA256(intended_client_SharedSecret, 16) // 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
		// fmt.Println(symmetric_key)
		encryptedData_y, err := aes.Encrypt(shares[i].Value, symmetric_key)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		Encrypt_piece := &auditor.SecreteSharePoint{
			Intended_Client: removed_client,
			Tag:             shares[i].Id,
			Encrypted_y:     encryptedData_y,
		}
		encrypt_secrete_array = append(encrypt_secrete_array, Encrypt_piece)
	}

	/// updating the database map
	database.SecreteShareMap[reportingClient.ID] = encrypt_secrete_array
	//// writing the update data to file
	updatedData, err := json.Marshal(database)
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

func removeRandomElement_int(slice []int) (int, []int) {
	index := randomInt(len(slice))
	removed := slice[index]
	return removed, append(slice[:index], slice[index+1:]...)
}

// //client reports to the auditor with decryption
func ClientReportDecryptedSecret(certauditor *auditor.Auditor, client *auditor.Client, missingClientID int) (*auditor.SecreteShareDecrypt, error) {
	/// read the database
	//// read the database first
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil, err
	}
	var database auditor.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil, err
	}
	/// find missing client's intended secrete piece
	secretes := database.SecreteShareMap[missingClientID]
	var missingClientPiece *auditor.SecreteSharePoint
	for i := 0; i < len(secretes); i++ {
		if secretes[i].Intended_Client == client.ID {
			missingClientPiece = secretes[i]
		}
	}
	if missingClientPiece == nil {
		// this client was not shared with a secrete
		return nil, nil
	}
	/// find the missing client's pub key
	missingClientPubKey, err := LocatePublicKeyWithID(missingClientID, database.Shuffle_PubKeys)
	if err != nil {
		log.Fatalf("client pubkey not found %v", err)
		return nil, err
	}
	/// find the missing client's shuffling order
	missingClientShuffleOrder, err := LocateShuffleOrderWithID(missingClientID, database.Shufflers_info)
	if err != nil {
		log.Fatalf("client Shuffle order not found %v", err)
		return nil, err
	}
	// compute d_j_i with for each database entry and return to auditor
	shared_secrete, err := elgamal.ECDH_bytes(missingClientPubKey.DH_Pub_H, client.DH_Pub_private)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	symmetric_key := aes.DeriveKeyFromSHA256(shared_secrete, 16)
	// fmt.Println(symmetric_key)
	decrypted_y, err := aes.Decrypt(missingClientPiece.Encrypted_y, symmetric_key)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	// fmt.Println()
	// fmt.Println("expected y", missingClientPiece.Y)
	// fmt.Println("actual y", decrypted_y)
	// fmt.Println()
	res_d_j_i := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		/// compute while treating the secrete piece as a piece
		d_ji, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[missingClientShuffleOrder], decrypted_y)
		if err != nil {
			log.Fatalf("secrete piece compute issue %v", err)
			return nil, err
		}
		res_d_j_i = append(res_d_j_i, d_ji)
	}

	return &auditor.SecreteShareDecrypt{
		Tag:           missingClientPiece.Tag,
		DecryptPieces: res_d_j_i,
	}, nil
}
