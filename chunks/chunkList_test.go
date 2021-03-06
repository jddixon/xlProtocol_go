package chunks

// xlProtocol_go/chunks/chunkList_test.go

import (
	"bytes"
	//"github.com/golang/x/crypto/sha3"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xi "github.com/jddixon/xlNodeID_go"
	xu "github.com/jddixon/xlUtil_go"
	. "gopkg.in/check.v1"
)

var _ = fmt.Print

// Calculate the chunk hash for the Nth chunk.
func (s *XLSuite) calculateChunkHash(c *C, n uint, datum []byte, data []byte) (
	chunkHash []byte) {

	chunkCount := uint((len(data) + MAX_DATA_BYTES - 1) / MAX_DATA_BYTES)
	c.Assert(0 <= n && n < chunkCount, Equals, true)

	// build the header
	b := make([]byte, DATUM_OFFSET)
	b = append(b, datum...)
	datumPadding := make([]byte, DATUM_PADDING)
	b = append(b, datumPadding...)

	// DEBUG
	fmt.Printf("after adding datum padding, packet len is %d\n",
		len(b))
	// END

	ch := &Chunk{packet: b}
	var chunkBytes int
	if chunkCount == 1 {
		chunkBytes = len(data)
		ch.packet = append(ch.packet, data...)
	} else if n == chunkCount-1 {
		chunkBytes = len(data) - int(n)*MAX_DATA_BYTES
		chunkData := data[n*MAX_DATA_BYTES:]
		ch.packet = append(ch.packet, chunkData...)
	} else {
		chunkBytes = MAX_DATA_BYTES
		ch.packet = append(ch.packet,
			data[n*MAX_DATA_BYTES:(n+1)*MAX_DATA_BYTES]...)
	}
	// we need to pad to a multiple of 16 bytes
	lenPadding := 16 - chunkBytes%16
	if lenPadding == 16 {
		lenPadding = 0
	}
	if lenPadding > 0 {
		padding := make([]byte, lenPadding)
		ch.packet = append(ch.packet, padding...)
	}
	ch.setIndex(uint32(n))
	ch.setLength(uint32(chunkBytes))

	// DEBUG
	fmt.Printf("  CHUNK %d of %6d bytes plus %2d bytes of padding\n",
		n, chunkBytes, lenPadding)
	fmt.Printf("    header: %x\n", ch.packet[0:DATUM_OFFSET])
	// END

	//d := sha3.NewKeccak256()
	d := sha1.New()
	d.Write(ch.packet)
	chunkHash = d.Sum(nil)
	// DEBUG
	// fmt.Printf("  ==> %s\n", hex.EncodeToString(chunkHash))
	// END
	//// DEBUG
	//if n == chunkCount - 1 {
	//	fmt.Println("DUMP OF LAST TEST CHUNK:")
	//	for j := 0; j < len(ch.packet); j += 16 {
	//		fmt.Printf("%6d %s\n", j,
	//			hex.EncodeToString(ch.packet[j: j + 16]))
	//	}
	//}
	//// END
	return
}
func (s *XLSuite) TestChunkList(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_CHUNK_LIST")
	}
	rng := xr.MakeSimpleRNG()

	dataLen := 1 + rng.Intn(3*MAX_DATA_BYTES)
	data := make([]byte, dataLen)
	rng.NextBytes(data)

	reader := bytes.NewReader(data)
	d := sha1.New()
	d.Write(data)
	datum := d.Sum(nil)
	nodeID, err := xi.NewNodeID(datum)
	c.Assert(err, IsNil)

	skPriv, err := rsa.GenerateKey(rand.Reader, 1024) // cheap key

	sk := &skPriv.PublicKey
	title := rng.NextFileName(8)
	timestamp := xu.Timestamp(rng.Int63())

	cl, err := NewChunkList(sk, title, timestamp, reader, int64(dataLen), datum, nil)
	c.Assert(err, IsNil)
	c.Assert(cl, NotNil)

	chunkCount := uint((dataLen + MAX_DATA_BYTES - 1) / MAX_DATA_BYTES)
	c.Assert(cl.Size(), Equals, chunkCount)

	for i := uint(0); i < chunkCount; i++ {
		actual, err := cl.HashItem(i)
		c.Assert(err, IsNil)
		expected := s.calculateChunkHash(c, i, datum, data)
		// DEBUG
		fmt.Printf("chunk %d hash\n    actual   %x\n    expected %x\n",
			i, actual, expected)
		// END
		//c.Assert(actual, DeepEquals, expected)

		// compare with result of calculation in NewChunk -----------
		var chunk *Chunk
		var slice []byte
		if i == chunkCount-1 {
			slice = data[i*MAX_DATA_BYTES:]
		} else {
			slice = data[i*MAX_DATA_BYTES : (i+1)*MAX_DATA_BYTES]
		}

		chunk, err = NewChunk(nodeID, uint32(i), slice)
		c.Assert(err, Equals, nil)
		c.Assert(chunk.GetChunkHash(), DeepEquals, expected)
	}

}
