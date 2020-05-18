package google_play

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
)

func readInt(payload []byte, start int) uint32 {
	return binary.BigEndian.Uint32(payload[start:len(payload)])
}
func toBigInt(payload []byte) big.Int {
	var result big.Int
	result.SetBytes(payload)
	return result
}

const (
	modulusOffset     = 4
	exponentLenOffset = 4
	exponentOffset    = 8
)

func encrypt(login, password string) string {
	/**
	structure of the binary key:
	*-------------------------------------------------------*
	| modulus_length | modulus | exponent_length | exponent |
	*-------------------------------------------------------*
	modulus_length and exponent_length are uint32
	*/
	loginUtf8 := []byte(login)
	passwordUtf8 := []byte(password)
	binaryKey, err := base64.StdEncoding.DecodeString(GooglePubkey)
	if err != nil {
		panic(err)
	}
	modulus, exponent := getModulusAndExponent(binaryKey)
	digest := sha1.New()
	digest.Write(binaryKey)
	h := digest.Sum([]byte("\x00"))[:5]

	pKey := rsa.PublicKey{N: &modulus, E: int(exponent.Int64())}
	var encryptMe []byte
	encryptMe = append(encryptMe, loginUtf8...)
	encryptMe = append(encryptMe, []byte("\x00")...)
	encryptMe = append(encryptMe, passwordUtf8...)
	rng := rand.Reader

	encrypted, err := rsa.EncryptOAEP(sha1.New(), rng, &pKey, encryptMe, nil)
	if err != nil {
		panic(err)
	}

	var encodeMe []byte
	encodeMe = append(encodeMe, h...)
	encodeMe = append(encodeMe, encrypted...)
	return base64.URLEncoding.EncodeToString(encodeMe)
}

func getModulusAndExponent(binaryKey []byte) (big.Int, big.Int) {
	modulusLen := readInt(binaryKey, 0)
	modulus := toBigInt(binaryKey[modulusOffset : modulusOffset+modulusLen])
	exponentLen := readInt(binaryKey, int(modulusLen+exponentLenOffset))
	exponent := toBigInt(binaryKey[int(modulusLen+exponentOffset):int(exponentLen+modulusLen+exponentOffset)])
	return modulus, exponent
}
