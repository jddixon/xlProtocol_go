package aes_cnx

// xlProtocol_go/aes_cnx/helloAndReply_test.go

import (
	"crypto/aes"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	. "gopkg.in/check.v1"
)

func (s *XLSuite) TestHelloAndReply(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_HELLO_AND_REPLY")
	}
	rng := xr.MakeSimpleRNG()

	ckPriv := s.makeAnRSAKey(c)
	ck := &ckPriv.PublicKey

	version1 := uint32(rng.Int31n(255 * 255)) // in effect an unsigned short

	// == HELLO =====================================================
	// On the client side, create and marshal a hello message containing
	// AES key1 and salt1 in addition to the client-proposed protocol version.

	cOneShot, ciphertext, err := ClientEncryptHello(version1, ck, rng)
	c.Assert(err, IsNil)
	key1 := cOneShot.Key
	c.Assert(len(key1), Equals, 2*aes.BlockSize)

	// On the server side: ------------------------------------------
	// Decrypt the hello using the node's private comms key, unpack.
	sOneShot, version1s, err := ServerDecryptHello(ciphertext, ckPriv, rng)
	c.Assert(err, IsNil)
	c.Assert(sOneShot.Key, DeepEquals, key1)
	c.Assert(version1s, Equals, version1)

	// == HELLO REPLY ===============================================
	// On the server side create, marshal a reply containing iv2, key2, salt2,
	// version2
	version2 := version1 // server accepts client proposal
	sSession, ciphertext, err := ServerEncryptHelloReply(sOneShot, version2)
	c.Assert(err, IsNil)
	c.Assert(sSession, NotNil)

	// On the client side: ------------------------------------------
	//     decrypt the reply using engine1b = iv1, key1

	cSession, version2c, err := ClientDecryptHelloReply(cOneShot, ciphertext)

	c.Assert(err, IsNil)
	c.Assert(cSession, NotNil)

	//c.Assert(cSession.Key, DeepEquals, key2c)	// XXX
	// c.Assert(key2c, DeepEquals, key2)		// XXX
	c.Assert(version2c, Equals, version1)

}
