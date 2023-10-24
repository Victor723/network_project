package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"web_cert_reporting/auditor"
	"web_cert_reporting/elgamal"
)

// NewAuditor creates a new Auditor instance
func NewClient(certauditor *auditor.Auditor, id int) *auditor.Client {
	k, err := certauditor.Curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	g := elgamal.Generate_Random_Dice_point(certauditor.Curve)
	h, err := elgamal.ECDH_bytes(g, k.Bytes())
	if err != nil {
		panic(err)
	}
	// fmt.Println(h)
	// fmt.Println()
	//TODO map msg to a curve
	return &auditor.Client{
		ID:             id,
		PrivateKey:     k,
		ReportingValue: elgamal.Generate_msg_bytes(certauditor.Curve),
		Curve:          certauditor.Curve,
		G:              g,
		H:              h,
	}
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
	h_r_i0, err := elgamal.ECDH_bytes(client.H, ri0)
	if err != nil {
		return nil, err
	}
	/// generate the first two item
	cert_times_h_r10, err := elgamal.Encrypt(h_r_i0, client.ReportingValue)
	if err != nil {
		return nil, err
	}
	// FIXED each client should have different g
	g_r_i0, err := elgamal.ECDH_bytes(client.G, ri0)
	if err != nil {
		return nil, err
	}
	/// generate the second two item
	ri1 := elgamal.Generate_Random_Dice_seed(client.Curve)
	if err != nil {
		return nil, err
	}
	h_r_i1, err := elgamal.ECDH_bytes(client.H, ri1)
	if err != nil {
		return nil, err
	}
	g_r_i1, err := elgamal.ECDH_bytes(client.G, ri1)
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
		shared_h_r_i_k, err := elgamal.ECDH_bytes(g_r_i_k, reportingClient.PrivateKey.Bytes())
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
				r_i_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
				g_r_i_prime, err := elgamal.ECDH_bytes(shuffler_info.G_i, r_i_prime)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				/// changing the shuffler entry
				database.Entries[i].Shufflers[shuffler_info.ID], err = elgamal.Encrypt(database.Entries[i].Shufflers[shuffler_info.ID], g_r_i_prime)
				if err != nil {
					log.Fatalf("%v", err)
					return err
				}
				/// changing the msg entry
				h_r_i_prime, err := elgamal.ECDH_bytes(shuffler_info.H_i, r_i_prime)
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
		ID:  len(database.Shufflers_info),
		H_i: reportingClient.H,
		G_i: reportingClient.G,
	}

	reportingClient.ShufflerID = len(database.Shufflers_info)
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
		ShufflerID: revealingClient.ShufflerID,
		Keys:       [][]byte{},
	}
	for i := 0; i < len(database.Entries); i++ {
		// check if this is my entry
		h_test, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, revealingClient.PrivateKey.Bytes())
		if err != nil {
			log.Fatalf("%v", err)
			return nil
		}

		if bytes.Equal(h_test, database.Entries[i].H_r_i1) {
			// it is my entry
			fmt.Print(revealingClient.ID)
			fmt.Println(" found entry")
			// fmt.Print(" found entry")
			add_two_gs, err := elgamal.Encrypt(database.Entries[i].Shufflers[revealingClient.ShufflerID], database.Entries[i].G_ri0)
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
			reveal_value_self, err := elgamal.ECDH_bytes(add_two_gs, revealingClient.PrivateKey.Bytes())

			revealRecords.Keys = append(revealRecords.Keys, reveal_value_self)
		} else {
			// it is not
			reveal_value_non_self, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[revealingClient.ShufflerID], revealingClient.PrivateKey.Bytes())
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
