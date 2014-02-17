package chunks

// xlattice_go/protocol/chunks/chunks_test.go

import (
	"bytes"
	"code.google.com/p/go.crypto/sha3"
	"fmt"
	xi "github.com/jddixon/xlattice_go/nodeID"
	xr "github.com/jddixon/xlattice_go/rnglib"
	. "launchpad.net/gocheck"
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
	bigData := make([]byte, MAX_CHUNK_BYTES+rng.Intn(3))
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
	c.Assert(int(ch.GetLength()), Equals, dataLen)
	c.Assert(ch.GetIndex(), Equals, ndx)
	actualDatum := ch.GetDatum()
	c.Assert(actualDatum, NotNil)
	c.Assert(bytes.Equal(actualDatum, datum.Value()), Equals, true)

	// field checks: data, chunk hash
	c.Assert(bytes.Equal(ch.GetData(), data), Equals, true)
	d := sha3.NewKeccak256()
	d.Write(ch.packet[0 : len(ch.packet)-HASH_BYTES])
	hash := d.Sum(nil)
	c.Assert(bytes.Equal(ch.GetChunkHash(), hash), Equals, true)
}
