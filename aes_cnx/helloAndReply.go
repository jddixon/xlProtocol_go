package aes_cnx

// xlProtocol_go/aes_cnx/helloAndReply.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	xr "github.com/jddixon/rnglib_go"
	xc "github.com/jddixon/xlCrypto_go"
)

// XXX SHOULDN'T RETURN KEY1 (IT's IN cOneShot)

// Create an AES IV and key and an 8-byte salt, then encrypt these and
// the proposed protocol version using the server's comms public key.
func ClientEncryptHello(version1 uint32, ck *rsa.PublicKey, rng *xr.PRNG) (
	ciphertext, key1, salt1 []byte, cOneShot *AesSession, err error) {
	
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

	key1 = salty[:2*aes.BlockSize]
	salt1 = salty[2*aes.BlockSize : 2*aes.BlockSize+8]
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
	key1s, salt1s []byte, version1s uint32, sOneShot *AesSession, err error) {

	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	sha := sha1.New()
	data, err := rsa.DecryptOAEP(sha, nil, ckPriv, ciphertext, nil)
	if err == nil {
		key1s = data[:2*aes.BlockSize]
		salt1s = data[2*aes.BlockSize : 2*aes.BlockSize+8]
		vBytes := data[2*aes.BlockSize+8:]
		version1s = uint32(vBytes[0]) |
			uint32(vBytes[1])<<8 |
			uint32(vBytes[2])<<16 |
			uint32(vBytes[3])<<24
		sOneShot, err = NewAesSession(key1s, rng)
	}
	return
}

// XXX sOneShot SHOULD BE PARAMETER; DOESN'T NEED key1 PARAM; 
// CAN USE sOneShot Key1 and RNG; SHOULD DO ENCRYPTION USING sOneShot

// Create and marshal using AES iv and key1 a reply prefixed by iv2
// and containing key2, salt2, salt1 and version 2, the server-decreed
// protocol version number.
func ServerEncryptHelloReply(sOneShot *AesSession, key1, salt1 []byte, 
	version2 uint32, rng *xr.PRNG) (
	key2, salt2, prefixedCiphertext []byte, sSession *AesSession, err error) {

	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	//var engine1a cipher.Block

	vBytes := make([]byte, 4)
	vBytes[0] = byte(version2)
	vBytes[1] = byte(version2 >> 8)
	vBytes[2] = byte(version2 >> 16)
	vBytes[3] = byte(version2 >> 24)

	data := make([]byte, 2*aes.BlockSize+8)	

	// make some random data
	rng.NextBytes(data)
	key2 = data[0: 2*aes.BlockSize]
	salt2 = data[2*aes.BlockSize : 2*aes.BlockSize+8]

	payload := data[0 : 2*aes.BlockSize+8] // so key2 + salt2
	// add the original salt, and then vBytes, representing version2
	payload = append(payload, salt1...)
	payload = append(payload, vBytes...)

	prefixedCiphertext, err = sOneShot.Encrypt(payload)

	//// XXX DO THE FOLLOWING WITH sOneShot: //////////////////////////

	//// We need padding because the message is not an integer multiple
	//// of the block size.
	//padded, err := xc.AddPKCS7Padding(payload, aes.BlockSize)
	//if err == nil {
	//	// encrypt the payload using engine1a = iv, key1
	//	engine1a, err = aes.NewCipher(key1) // on server
	//}
	//if err == nil {
	//	aesEncrypter1a := cipher.NewCBCEncrypter(engine1a, iv)

	//	// we require that the message size be a multiple of the block size
	//	// XXXX IT's an internal error if it isn't.
	//	msgLen := len(padded)
	//	nBlocks := (msgLen + aes.BlockSize - 1) / aes.BlockSize
	//	ciphertext := make([]byte, nBlocks*aes.BlockSize)
	//	aesEncrypter1a.CryptBlocks(ciphertext, padded) // dest <- src
	//	// XXX FIX ME: This should be a __copy__ of iv
	//	prefixedCiphertext = iv // just to make things clear ...
	//	prefixedCiphertext = append(prefixedCiphertext, ciphertext...)
	//}
	//// END STUFF DONE BY sOneShot ///////////////////////////////////
	if err == nil {
		sSession, err = NewAesSession(key2, rng)
	}
	return
}

// XXX cOneShot SHOULD BE PARAMETER; DOESN'T NEED key1 PARAM; 
// CAN USE sOneShot Key1 and RNG

// Decrypt the reply using AES key1, then decode from the reply
// key2, an 8-byte salt2, and the original salt1.
//
func ClientDecryptHelloReply(cOneShot *AesSession, prefixedCiphertext, 
	key1 []byte, rng *xr.PRNG) (
	key2, salt2, salt1 []byte, version2 uint32, cSession *AesSession, err error) {

	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	var unpaddedReply []byte

	// XXX DO THIS USING cOneShot: //////////////////////////////////

	engine1b, err := aes.NewCipher(key1) // on client
	if err == nil {
		iv := prefixedCiphertext[:aes.BlockSize]
		ciphertext := prefixedCiphertext[aes.BlockSize:]
		aesDecrypter1b := cipher.NewCBCDecrypter(engine1b, iv)
		plaintext := make([]byte, len(ciphertext))
		aesDecrypter1b.CryptBlocks(plaintext, ciphertext) // dest <- src
		unpaddedReply, err = xc.StripPKCS7Padding(plaintext, aes.BlockSize)
	}
	if err == nil {
		key2 = unpaddedReply[:2*aes.BlockSize]
		salt2 = unpaddedReply[2*aes.BlockSize : 2*aes.BlockSize+8]
		salt1 = unpaddedReply[2*aes.BlockSize+8 : 2*aes.BlockSize+16]

		vBytes2 := unpaddedReply[2*aes.BlockSize+16 : 2*aes.BlockSize+20]
		version2 = uint32(vBytes2[0]) |
			(uint32(vBytes2[1]) << 8) |
			(uint32(vBytes2[2]) << 16) |
			(uint32(vBytes2[3]) << 24)
	} 
	// END STUFF DONE BY cOneShot ///////////////////////////////////

	if err == nil {
		cSession, err = NewAesSession(key2, rng)
	}
	return
}
