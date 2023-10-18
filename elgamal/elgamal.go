package elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"
)

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

func Generate_msg_bytes() []byte {
	randomBigInt, err := randBigInt(2048)
	if err != nil {
		panic(err)
	}
	return randomBigInt.Bytes()
}

func Generate_one_bytes() []byte {
	return big.NewInt(1).Bytes()
}
func IsZero(bigInt *big.Int) bool {
	return bigInt.Sign() == 0
}

func Encrypt(shared_secret []byte, msg []byte) ([]byte, error) {
	shared_secret_int := new(big.Int).SetBytes(shared_secret)
	msg_int := new(big.Int).SetBytes(msg)
	if IsZero(msg_int) {
		return nil, errors.New("message can not be zero")
	}
	return shared_secret_int.Mul(shared_secret_int, msg_int).Bytes(), nil
}

func Decrypt(shared_secret []byte, cyphertext []byte) ([]byte, error) {
	cyphertext_int := new(big.Int).SetBytes(cyphertext)
	shared_secret_int := new(big.Int).SetBytes(shared_secret)
	return shared_secret_int.Div(cyphertext_int, shared_secret_int).Bytes(), nil
}
