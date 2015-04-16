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
	// AES key1, salt1 in addition to the client-proposed protocol version.

	ciphertext, key1, salt1, err := ClientEncodeHello(version1, ck)
	c.Assert(err, IsNil)
	c.Assert(len(key1), Equals, 2*aes.BlockSize)
	c.Assert(len(salt1), Equals, 8)

	// On the server side: ------------------------------------------
	// Decrypt the hello using the node's private comms key, unpack.
	key1s, salt1s, version1s, err := ServerDecodeHello(ciphertext, ckPriv)
	c.Assert(err, IsNil)

	c.Assert(key1s, DeepEquals, key1)
	c.Assert(salt1s, DeepEquals, salt1)
	c.Assert(version1s, Equals, version1)

	// == HELLO REPLY ===============================================
	// On the server side create, marshal a reply containing iv2, key2, salt2,
	// salt1, version2
	version2 := version1 // server accepts client proposal
	key2, salt2, ciphertext, err := ServerEncodeHelloReply(
		key1, salt1, version2)
	c.Assert(err, IsNil)

	// On the client side: ------------------------------------------
	//     decrypt the reply using engine1b = iv1, key1

	key2c, salt2c, salt1c, version2c, err := ClientDecodeHelloReply(
		ciphertext, key1)

	c.Assert(err, IsNil)

	c.Assert(key2c, DeepEquals, key2)
	c.Assert(salt2c, DeepEquals, salt2)
	c.Assert(salt1c, DeepEquals, salt1)
	c.Assert(version2c, Equals, version1)

}
