package aes_cnx

// xlProtocol_go/aes_cnx/helloAndReply.go

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
)

var _ = fmt.Printf

// Create an AES IV and key and an 8-byte salt, then encrypt these and
// the proposed protocol version using the server's comms public key.
func ClientEncryptHello(version1 uint32, ck *rsa.PublicKey, rng *xr.PRNG) (
	cOneShot *AesSession, ciphertext []byte, err error) {

	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	vBytes := make([]byte, 4)
	vBytes[0] = byte(version1)
	vBytes[1] = byte(version1 >> 8)
	vBytes[2] = byte(version1 >> 16)
	vBytes[3] = byte(version1 >> 24)

	// Generate 32-byte AES key, and 8-byte salt for the Hello
	salty := make([]byte, 2*aes.BlockSize+8+20)
	rng.NextBytes(salty)

	key1 := salty[:2*aes.BlockSize]
	// salt1 := salty[2*aes.BlockSize : 2*aes.BlockSize+8]
	oaep1 := salty[2*aes.BlockSize+8:]
	oaepSalt := bytes.NewBuffer(oaep1)

	sha := sha1.New()
	data := salty[:2*aes.BlockSize+8] // contains key1,salt1
	data = append(data, vBytes...)    // ... plus preferred protocol version

	ciphertext, err = rsa.EncryptOAEP(sha, oaepSalt, ck, data, nil)
	if err == nil {
		cOneShot, err = NewAesSession(key1, rng)
	}
	return
}

// Decrypt the Hello using the node's private comms key, and decode its
// contents.
func ServerDecryptHello(ciphertext []byte, ckPriv *rsa.PrivateKey, rng *xr.PRNG) (
	sOneShot *AesSession, version1s uint32, err error) {
	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	sha := sha1.New()
	data, err := rsa.DecryptOAEP(sha, nil, ckPriv, ciphertext, nil)
	// DEBUG
	if err == nil {
		expectedLen := 2*aes.BlockSize + 12
		if len(data) != expectedLen {
			fmt.Printf("expected OAEP packet len %d, actual %d bytes\n",
				expectedLen, len(data))
			err = WrongOAEPSize // XXX BAD NAME
		}
	}
	// END
	if err == nil {
		key1s := data[:2*aes.BlockSize]
		// salt1s = data[2*aes.BlockSize : 2*aes.BlockSize+8]
		vBytes := data[2*aes.BlockSize+8:]
		version1s = uint32(vBytes[0]) |
			uint32(vBytes[1])<<8 |
			uint32(vBytes[2])<<16 |
			uint32(vBytes[3])<<24
		sOneShot, err = NewAesSession(key1s, rng)
	}
	return
}

// Create and marshal using AES key1 a reply prefixed by iv2
// and containing key2, salt2, and version 2, the server-decreed
// protocol version number.
func ServerEncryptHelloReply(sOneShot *AesSession, version2 uint32) (
	sSession *AesSession, pCiphertext []byte, err error) {

	rng := sOneShot.RNG

	vBytes := make([]byte, 4)
	vBytes[0] = byte(version2)
	vBytes[1] = byte(version2 >> 8)
	vBytes[2] = byte(version2 >> 16)
	vBytes[3] = byte(version2 >> 24)

	data := make([]byte, 2*aes.BlockSize+8)

	// make some random data
	rng.NextBytes(data)
	key2 := data[0 : 2*aes.BlockSize]
	// salt2 := data[2*aes.BlockSize : 2*aes.BlockSize+8]

	payload := data[0 : 2*aes.BlockSize+8] // so key2 + salt2
	// add vBytes, representing version2
	payload = append(payload, vBytes...)
	pCiphertext, err = sOneShot.Encrypt(payload)

	if err == nil {
		sSession, err = NewAesSession(key2, rng)
	}
	return
}

// Decrypt the reply using AES key1, then decode from the reply key2.
//
func ClientDecryptHelloReply(cOneShot *AesSession, pCiphertext []byte) (
	cSession *AesSession, version2 uint32, err error) {

	var key2 []byte
	rng := cOneShot.RNG
	unpaddedReply, err := cOneShot.Decrypt(pCiphertext)

	if err == nil {
		key2 = unpaddedReply[:2*aes.BlockSize]
		// salt2 := unpaddedReply[2*aes.BlockSize : 2*aes.BlockSize+8]

		vBytes2 := unpaddedReply[2*aes.BlockSize+8 : 2*aes.BlockSize+12]
		version2 = uint32(vBytes2[0]) |
			(uint32(vBytes2[1]) << 8) |
			(uint32(vBytes2[2]) << 16) |
			(uint32(vBytes2[3]) << 24)
	}

	if err == nil {
		cSession, err = NewAesSession(key2, rng)
	}
	return
}
