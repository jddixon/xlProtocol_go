package aes_cnx

// xlProtocol_go/aes_cnx/aesSession_test.go

import (
	"crypto/aes"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	. "gopkg.in/check.v1"
)

// Make a message (or reply) of up to 16 AES blocks in size and stuff
// it with random bytes.  Return the message with PKCS7-padded appended.
//
func (s *XLSuite) MakeAMsg(c *C, rng *xr.PRNG) (
	msg []byte, msgLen int) {

	msgLen = 2 + rng.Intn(16*aes.BlockSize-2)
	msg = make([]byte, msgLen)
	rng.NextBytes(msg)
	return
}
func (s *XLSuite) doTestAesSession(c *C, rng *xr.PRNG) {

	// SESSION SETUP ================================================

	// A->B half circuit ----------------------------------
	keyAB := make([]byte, 2*aes.BlockSize)
	rng.NextBytes(keyAB)

	// set up A side of A->B half-circuit
	hAOut, err := NewAesSession(keyAB, rng)
	c.Assert(err, IsNil)
	c.Assert(hAOut.Engine, NotNil)

	// set up B side of A->B half-circuit
	hBIn, err := NewAesSession(keyAB, rng)
	c.Assert(err, IsNil)
	c.Assert(hBIn.Engine, NotNil)

	// B->A half circuit ----------------------------------
	keyBA := make([]byte, 2*aes.BlockSize)
	rng.NextBytes(keyBA)

	// set up B side of B->A half-circuit
	hBOut, err := NewAesSession(keyBA, rng)
	c.Assert(err, IsNil)
	c.Assert(hBOut.Engine, NotNil)

	// set up A side of B->A half-circuit
	hAIn, err := NewAesSession(keyBA, rng)
	c.Assert(err, IsNil)
	c.Assert(hAIn.Engine, NotNil)

	// for N messages initiated by A
	N := 4
	for n := 0; n < N; n++ {
		// A create a random-ish message ----------------------------
		msg, msgSize := s.MakeAMsg(c, rng)

		// encrypt it, yielding abCiphertext, which is prefixed with the IV
		abCiphertext, ivA, err := hAOut.Encrypt(msg)
		c.Assert(err, IsNil)

		//   B decrypts msg -----------------------------------------
		unpaddedMsg, ivAb, err := hBIn.Decrypt(abCiphertext)
		c.Assert(err, IsNil)
		c.Assert(ivAb, DeepEquals, ivA)

		c.Assert(len(unpaddedMsg), Equals, msgSize)
		c.Assert(unpaddedMsg, DeepEquals, msg)

		// B create a random-ish message ----------------------------
		reply, replySize := s.MakeAMsg(c, rng)

		// encrypt it, yielding baCiphertext, which is prefixed with the IV
		baCiphertext, ivB, err := hBOut.Encrypt(reply)
		c.Assert(err, IsNil)

		//   A decrypts reply -----------------------------------------
		unpaddedReply, ivBb, err := hAIn.Decrypt(baCiphertext)
		c.Assert(err, IsNil)
		c.Assert(ivBb, DeepEquals, ivB)

		c.Assert(len(unpaddedReply), Equals, replySize)
		c.Assert(unpaddedReply, DeepEquals, reply)
	}
}

func (s *XLSuite) TestAesSession(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("\nTEST_AES_CNX")
	}
	rng := xr.MakeSimpleRNG()

	K := 4 // NOTE
	for k := 0; k < K; k++ {
		s.doTestAesSession(c, rng)
	}
}
