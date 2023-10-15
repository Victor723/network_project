package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type CipherText struct {
	X1, Y1, X2, Y2 *big.Int
}

func GenerateKey(curve elliptic.Curve) (*PrivateKey, error) {
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{Curve: curve, X: x, Y: y},
		D:         new(big.Int).SetBytes(priv),
	}, nil
}

func Encrypt(pub *PublicKey, msg []byte) (*CipherText, error) {
	k, err := rand.Int(rand.Reader, pub.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	x1, y1 := pub.Curve.ScalarBaseMult(k.Bytes())

	xm, ym := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	r, s := elliptic.Unmarshal(pub.Curve, msg)
	if r == nil {
		return nil, fmt.Errorf("failed to unmarshal message")
	}

	x2, y2 := pub.Curve.Add(r, s, xm, ym)

	return &CipherText{
		X1: x1, Y1: y1,
		X2: x2, Y2: y2,
	}, nil
}

func Decrypt(priv *PrivateKey, cipher *CipherText) ([]byte, error) {
	xm, ym := priv.Curve.ScalarMult(cipher.X1, cipher.Y1, priv.D.Bytes())

	// Negate the y-coordinate to get the inverse point.
	negYm := new(big.Int).Sub(priv.Curve.Params().P, ym)

	x, y := priv.Curve.Add(cipher.X2, cipher.Y2, xm, negYm)

	return elliptic.Marshal(priv.Curve, x, y), nil
}

func main() {
	curve := elliptic.P256()

	// Generate key
	priv, err := GenerateKey(curve)
	if err != nil {
		panic(err)
	}

	// Sample message (as an elliptic curve point)
	msg := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)

	// Encrypt
	ciphertext, err := Encrypt(&priv.PublicKey, msg)
	if err != nil {
		panic(err)
	}

	// Decrypt
	decrypted, err := Decrypt(priv, ciphertext)
	if err != nil {
		panic(err)
	}

	// Check
	if string(decrypted) == string(msg) {
		fmt.Println("Decryption successful!")
	} else {
		fmt.Println("Decryption failed!")
	}
}