package aes_cnx

// xlProtocol/aes_cnx/aesSession.go

import (
	"crypto/aes"
	"crypto/cipher"
	xr "github.com/jddixon/rnglib_go"
	xc "github.com/jddixon/xlCrypto_go"
)

// XXX NOT CURRENTLY USED
const (
	MSG_BUF_LEN = 16 * 1024
)

type AesSession struct {
	State      int
	Engine     cipher.Block
	Key1, Key2 []byte // Key1 is uhm maybe
	RNG        *xr.PRNG
}

// An AesSession establishes one side of a two-sided relationship.  Encryption
// and decryption share the same key (although per-direction keys could be
// supported in a slightly different implementation).  If a random number
// generator (RNG) is not supplied, it uses a secure (and expensive) system 
// RNG.  If no key is supplied it creates a random 256-bit AES key.
//
func NewAesSession(key []byte, rng *xr.PRNG) (session *AesSession, err error) {
	if rng == nil {
		rng = xr.MakeSystemRNG()
	}
	if key == nil || len(key) == 0 {
		key = make([]byte, 2*aes.BlockSize)
	}
	engine, err := aes.NewCipher(key)
	if err == nil {
		session = &AesSession{
			Engine: engine,
			Key2:   key,
			RNG:    rng,
		}
	}
	return session, err
}

// IV is currently being returned for debugging; this should stop as it
// is prefixed to the ciphertext returned and easily extracted.
//
func (as *AesSession) encryptMsg(msg []byte) (
	prefixedCiphertext, iv []byte, err error) {

	paddedMsg, err := xc.AddPKCS7Padding(msg, aes.BlockSize)
	if err == nil {
    	// chooose an IV to set up encrypter (later prefix to the padded msg)
    	iv = make([]byte, aes.BlockSize)
    	as.RNG.NextBytes(iv)
    
    	encrypter := cipher.NewCBCEncrypter(as.Engine, iv)
    	ciphertext := make([]byte, len(paddedMsg))
    	encrypter.CryptBlocks(ciphertext, paddedMsg) // dest <- src
    
    	prefixedCiphertext = make([]byte, len(iv))
    	copy(prefixedCiphertext, iv) // dest <- src
    	prefixedCiphertext = append(prefixedCiphertext, ciphertext...)
    }
	return
}

// IV is currently being returned for debugging; this should stop as 
// it is part of prefixedData supplied by the caller.
//
// prefixedData consists of the iv prefixed to the ciphertext.
//
func (as *AesSession) decryptCiphertext(prefixedData []byte) (
	unpaddedMsg, iv []byte, err error) {

	// prefixedData is prefixed with the (plaintext) IV
	iv = prefixedData[0:aes.BlockSize]
	ciphertext := prefixedData[aes.BlockSize:]
	paddedLen := len(ciphertext)
	decrypter := cipher.NewCBCDecrypter(as.Engine, iv)
	plaintext := make([]byte, paddedLen)
	decrypter.CryptBlocks(plaintext, ciphertext) // dest <- src
	unpaddedMsg, err = xc.StripPKCS7Padding(plaintext, aes.BlockSize)
	return
}
