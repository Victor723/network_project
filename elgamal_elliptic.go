package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// type PublicKey struct {
// 	Curve elliptic.Curve
// 	X, Y  *big.Int
// }

// type PrivateKey struct {
// 	PublicKey
// 	D *big.Int
// }

// type CipherText struct {
// 	X1, Y1, X2, Y2 *big.Int
// }

// // func GenerateKey(curve elliptic.Curve) (*PrivateKey, error) {
// // 	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	return &PrivateKey{
// // 		PublicKey: PublicKey{Curve: curve, X: x, Y: y},
// // 		D:         new(big.Int).SetBytes(priv),
// // 	}, nil
// // }

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
	report_msg := generate_msg_bytes()
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

	for _, b := range report_msg {
		fmt.Printf("%x ", b)
	}

	fmt.Println()
	fmt.Println()
	fmt.Println()
	for _, b := range plaintext {
		fmt.Printf("%x ", b)
	}
	fmt.Println()
	if string(report_msg) == string(plaintext) {
		fmt.Println("Decryption successful!")
	} else {
		fmt.Println("Decryption failed!")
	}

}
