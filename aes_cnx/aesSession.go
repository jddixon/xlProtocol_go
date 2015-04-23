package aes_cnx

// xlProtocol/aes_cnx/aesSession.go

// Assume that a generator for this code is parameterized by
//	package name	- defaults to using local directory name
//  protocol name	- defaults to using whatever precedes "Msg" in *.proto
//  MSG_BUF_LEN		- defaults to 16 (K assumed)
//  file name		- defaults to protocol name + "_aes_cnx.go"
//  struct name		- defaults to protocol name + "AesSession"
//
// Generator is tested by generating the text for xlReg_go/reg
// and then comparing it to this file, with this comment block dropped.

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
	engine     cipher.Block
	key1, key2 []byte // key1 is uhm maybe
	rng        *xr.PRNG
}

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
			engine: engine,
			key2:   key,
			rng:    rng,
		}
	}
	return session, err
}

// IV is currently being returned for debugging; this should stop.
//
// XXX RESPEC SO THAT THE PADDING IS DONE HERE
func (as *AesSession) encryptMsg(paddedMsg []byte) (
	prefixedCiphertext, iv []byte) {

	// chooose an IV to set up encrypter (later prefix to the padded msg)
	iv = make([]byte, aes.BlockSize)
	as.rng.NextBytes(iv)

	encrypter := cipher.NewCBCEncrypter(as.engine, iv)
	ciphertext := make([]byte, len(paddedMsg))
	encrypter.CryptBlocks(ciphertext, paddedMsg) // dest <- src

	prefixedCiphertext = make([]byte, len(iv))
	copy(prefixedCiphertext, iv) // dest <- src
	prefixedCiphertext = append(prefixedCiphertext, ciphertext...)

	return
}

// IV is currently being returned for debugging; this should stop.
//
// XXX SIMPLIFY NAMES OF INTERNAL VARIABLES
func (as *AesSession) decryptCiphertext(abCiphertext []byte) (
	unpaddedMsg, iv []byte, err error) {

	// abCiphertext is prefixed with the (plaintext) IV
	iv = abCiphertext[0:aes.BlockSize]
	ciphertext := abCiphertext[aes.BlockSize:]
	paddedLen := len(ciphertext)
	decrypter := cipher.NewCBCDecrypter(as.engine, iv)
	plaintext := make([]byte, paddedLen)
	decrypter.CryptBlocks(plaintext, ciphertext) // dest <- src
	unpaddedMsg, err = xc.StripPKCS7Padding(plaintext, aes.BlockSize)
	return
}
