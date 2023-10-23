package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
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
	return &auditor.Client{ID: id, PrivateKey: k, ReportingValue: elgamal.Generate_msg_bytes(certauditor.Curve), Curve: certauditor.Curve}
}

func ReadDatabase(certauditor *auditor.Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.FileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func CreateInitialEntry(client *auditor.Client) (*auditor.ReportingEntry, error) {
	ri0, err := client.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h_r_i0, err := elgamal.ECDH_returnPoint(ri0, client.PrivateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	/// generate the first two item
	cert_times_h_r10, err := elgamal.Encrypt(h_r_i0, client.ReportingValue)
	if err != nil {
		return nil, err
	}
	// TODO g always starts from base point
	g_r_i0 := ri0.PublicKey().Bytes()
	/// generate the second two item
	ri1, err := client.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h_r_i1, err := elgamal.ECDH_returnPoint(ri1, client.PrivateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	g_r_i1 := ri1.PublicKey().Bytes()
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
	var database *auditor.Database

	// Unmarshal the byte slice into the 'person' variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}
	if len(database.Shufflers_info) == 0 {
		//  TODO more robust checks needed
		// first shuffle
		// randomize
	} else {

	}
	return nil
}

// Shuffle securely shuffles the order of the input slice.
func Shuffle(slice []*auditor.ReportingEntry) {
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
