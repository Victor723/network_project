package elgamal

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"math/big"

	"filippo.io/nistec"
)

const web_cert_len = 2048

func ECDH_returnPoint(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	seed := priv.Bytes()
	pub_point, err := nistec.NewP256Point().SetBytes(pub.Bytes())
	if err != nil {
		return nil, errors.New("pub key is not a point on the curve")
	}
	pub_point.ScalarMult(pub_point, seed)
	return pub_point.Bytes(), nil
}

func ECDH_bytes(point []byte, scalar []byte) ([]byte, error) {
	pub_point, err := nistec.NewP256Point().SetBytes(point)
	if err != nil {
		return nil, errors.New("the provided point is not a point on the curve")
	}
	pub_point.ScalarMult(pub_point, scalar)
	return pub_point.Bytes(), nil
}

func Encrypt(shared_secret []byte, msg []byte) ([]byte, error) {
	/// assuming curve here, TODO Add the curve type
	shared_secret_point, err := nistec.NewP256Point().SetBytes(shared_secret)
	if err != nil {
		return nil, errors.New("shared secrete is not a point on the curve")
	}
	msg_point, err := nistec.NewP256Point().SetBytes(msg)
	if err != nil {
		return nil, errors.New("msg is not a point on the curve")
	}
	res := nistec.NewP256Point()
	if err != nil {
		return nil, errors.New("something wrong in the library")
	}
	res.Add(shared_secret_point, msg_point)
	return res.Bytes(), nil
}

func Decrypt(shared_secret []byte, cyphertext []byte) ([]byte, error) {
	/// assuming curve here, TODO Add the curve type
	shared_secret_point, err := nistec.NewP256Point().SetBytes(shared_secret)
	if err != nil {
		return nil, errors.New("shared secrete is not a point on the curve")
	}
	cyphertext_point, err := nistec.NewP256Point().SetBytes(cyphertext)
	if err != nil {
		return nil, errors.New("msg is not a point on the curve")
	}

	shared_secret_point.Negate(shared_secret_point)
	res := nistec.NewP256Point()
	if err != nil {
		return nil, errors.New("something wrong in the library")
	}
	res.Add(cyphertext_point, shared_secret_point)
	return res.Bytes(), nil
}

func Generate_msg_bytes(curve ecdh.Curve) []byte {
	/// generate a random point of the elliptic curve, and just return the message
	new_p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return new_p.PublicKey().Bytes()
}

func IsZero(bigInt *big.Int) bool {
	return bigInt.Sign() == 0
}

func Generate_Random_Dice_seed(curve ecdh.Curve) []byte {
	new_p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return new_p.Bytes()
}

func Generate_Random_Dice_point(curve ecdh.Curve) []byte {
	new_p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return new_p.PublicKey().Bytes()
}

func Convert_seed_To_point(seed []byte, curve ecdh.Curve) ([]byte, error) {
	new_p, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, errors.New("seed not valid")
	}
	res := new_p.PublicKey().Bytes()
	return res, nil
}
