package chunks

// xlProtocol_go/chunks/chunk_test.go

import (
	"bytes"
	//"github.com/golang/x/crypto/sha3"
	"crypto/sha1"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xi "github.com/jddixon/xlNodeID_go"
	. "gopkg.in/check.v1"
)

var _ = fmt.Print

func (s *XLSuite) TestConstants(c *C) {
	c.Assert(MAGIC_OFFSET, Equals, 0)
	c.Assert(TYPE_OFFSET, Equals, 1)
	c.Assert(RESERVED_OFFSET, Equals, 2)
	c.Assert(LENGTH_OFFSET, Equals, 8)
	c.Assert(INDEX_OFFSET, Equals, 12)
	c.Assert(DATUM_OFFSET, Equals, 16)
	c.Assert(DATA_OFFSET, Equals, 48)
}

func (s *XLSuite) TestProperties(c *C) {
	rng := xr.MakeSimpleRNG()
	_ = rng

}

func (s *XLSuite) TestBadLengths(c *C) {

	datum, err := xi.New(nil) // generates random NodeID

	rng := xr.MakeSimpleRNG()
	ndx := uint32(rng.Intn(256 * 256 * 256))
	okData := make([]byte, 256+rng.Intn(3))

	// verify nil datum causes error
	nilChunk, err := NewChunk(nil, ndx, okData)
	c.Assert(err, Equals, NilDatum)
	c.Assert(nilChunk, Equals, (*Chunk)(nil))

	// verify nil data causes error
	nilChunk, err = NewChunk(datum, ndx, nil)
	c.Assert(err, Equals, NilData)
	c.Assert(nilChunk, Equals, (*Chunk)(nil))

	// verify length of zero causes error
	zeroLenData := make([]byte, 0)
	lenZeroChunk, err := NewChunk(datum, ndx, zeroLenData)
	c.Assert(err, Equals, ZeroLengthChunk)
	c.Assert(lenZeroChunk, Equals, (*Chunk)(nil))

	// verify length > MAX_CHUNK_BYTES causes error
	bigData := make([]byte, MAX_CHUNK_BYTES+1+rng.Intn(3))
	tooBig, err := NewChunk(datum, ndx, bigData)
	c.Assert(err, Equals, ChunkTooLong)
	c.Assert(tooBig, Equals, (*Chunk)(nil))
}

func (s *XLSuite) TestChunks(c *C) {
	rng := xr.MakeSimpleRNG()

	ndx := uint32(rng.Int31())
	datum, err := xi.New(nil)
	c.Assert(err, IsNil)
	dataLen := 1 + rng.Intn(256*256) // 1 .. 2^16
	data := make([]byte, dataLen)
	rng.NextBytes(data)
	ch, err := NewChunk(datum, ndx, data)
	c.Assert(err, IsNil)
	c.Assert(ch, NotNil)

	// field checks: magic, type, reserved
	c.Assert(ch.Magic(), Equals, byte(0))
	c.Assert(ch.Type(), Equals, byte(0))
	expectedReserved := make([]byte, 6)
	c.Assert(bytes.Equal(expectedReserved, ch.Reserved()), Equals, true)

	// field checks: length, index, datum (= hash of overall message)
	c.Assert(int(ch.GetDataLen()), Equals, dataLen)
	c.Assert(ch.GetIndex(), Equals, ndx)
	actualDatum := ch.GetDatum()
	c.Assert(actualDatum, NotNil)
	// DEBUG
	//fmt.Printf("actualDatum: %x\n", actualDatum)
	//fmt.Printf("datum:       %x\n", datum.Value())
	// END
	c.Assert(bytes.Equal(actualDatum, datum.Value()), Equals, true)

	// field checks: data, chunk hash
	// DEBUG
	//fmt.Printf("data:       %x\n", data)
	//fmt.Printf("from chunk: %x\n", ch.GetData())
	// END
	c.Assert(bytes.Equal(ch.GetData(), data), Equals, true)
	//d := sha3.NewKeccak256()
	d := sha1.New()
	d.Write(ch.packet[0 : len(ch.packet)-HASH_BYTES])
	hash := d.Sum(nil)
	// DEBUG
	//fmt.Printf("TestChunks:\n    hash in chunk %x\n    calculated    %x\n",
	//	ch.GetChunkHash(), hash)
	// END
	c.Assert(bytes.Equal(ch.GetChunkHash(), hash), Equals, true)
}
