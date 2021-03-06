package chunks

// xlProtocol_go/chunks/chunk.go

import (
	"crypto/sha1"
	//"github.com/golang/x/crypto/sha3"
	"encoding/binary"
	"fmt"
	xi "github.com/jddixon/xlNodeID_go"
)

var _ = fmt.Print

type Chunk struct {
	packet []byte
}

// Datum is declared a NodeID to restrict its value to certain byteslice
// lengths.
func NewChunk(datum *xi.NodeID, ndx uint32, data []byte) (
	ch *Chunk, err error) {

	if datum == nil {
		err = NilDatum
	} else if data == nil {
		err = NilData
	} else if len(data) == 0 {
		err = ZeroLengthChunk
	} else if len(data) > MAX_CHUNK_BYTES {
		err = ChunkTooLong
	} else {
		msgHash := datum.Value()
		realLen := len(data)
		adjLen := ((realLen + WORD_BYTES - 1) / WORD_BYTES) * WORD_BYTES
		paddingBytes := adjLen - realLen
		packet := make([]byte, DATUM_OFFSET)
		datumPadding := make([]byte, DATUM_PADDING)
		ch = &Chunk{packet: packet}
		ch.setLength(uint32(realLen)) // length of the data part
		ch.setIndex(ndx)              // index of this chunk in overall message
		ch.packet = append(ch.packet, msgHash...)
		ch.packet = append(ch.packet, datumPadding...)
		ch.packet = append(ch.packet, data...)
		if paddingBytes > 0 {
			padding := make([]byte, paddingBytes)
			ch.packet = append(ch.packet, padding...)
		}
		// calculate the SHA1 hash of the chunk
		d := sha1.New()
		d.Write(ch.packet)
		chunkHash := d.Sum(nil)

		// append that to the packet
		ch.packet = append(ch.packet, chunkHash...)
	}
	return
}

func (ch *Chunk) Magic() byte {
	return ch.packet[MAGIC_OFFSET]
}

func (ch *Chunk) Type() byte {
	return ch.packet[TYPE_OFFSET]
}

func (ch *Chunk) Reserved() []byte {
	return ch.packet[RESERVED_OFFSET : RESERVED_OFFSET+RESERVED_BYTES]
}

// Return the length encoded in the packet.  This is the actual length
// of the data in bytes, excluding any padding added.  The value actually
// stored is the length less one.
//
func (ch *Chunk) GetDataLen() uint32 {
	return binary.BigEndian.Uint32(
		ch.packet[LENGTH_OFFSET : LENGTH_OFFSET+LENGTH_BYTES])
}

// Store the length of the data, which must not be zero and must
// not exceed MAX_DATA_BYTES = MAX_CHUNK_BYTES - (headerSize + hashSize)
func (ch *Chunk) setLength(n uint32) {
	binary.BigEndian.PutUint32(
		ch.packet[LENGTH_OFFSET:LENGTH_OFFSET+LENGTH_BYTES], n)
}

// We store the actual value of the zero-based index.
func (ch *Chunk) GetIndex() uint32 {
	return binary.BigEndian.Uint32(
		ch.packet[INDEX_OFFSET : INDEX_OFFSET+INDEX_BYTES])
}

func (ch *Chunk) setIndex(n uint32) {
	binary.BigEndian.PutUint32(
		ch.packet[INDEX_OFFSET:INDEX_OFFSET+INDEX_BYTES], n)
}

// Given a byte slice, determine the length of a chunk wrapping it:
// /header + data + chunk hash.
func (ch *Chunk) CalculateLength(data []byte) uint32 {
	dataLen := ((len(data) + WORD_BYTES - 1) / WORD_BYTES) * WORD_BYTES
	return uint32(DATA_OFFSET + dataLen + HASH_BYTES)
}

// Return the chunk's datum.  This is the content key for the message
// of which this chunk is a part.
func (ch *Chunk) GetDatum() []byte {
	return ch.packet[DATUM_OFFSET : DATUM_OFFSET+DATUM_BYTES]
}

// Return the slice of data in the chunk.  This is NOT a copy.
func (ch *Chunk) GetData() []byte {
	return ch.packet[DATA_OFFSET : DATA_OFFSET+ch.GetDataLen()]
}

// Retrieve the packet hash
func (ch *Chunk) GetChunkHash() []byte {
	dataLen := ch.GetDataLen()
	hashOffset := ((dataLen + DATA_OFFSET + WORD_BYTES - 1) /
		WORD_BYTES) * WORD_BYTES
	return ch.packet[hashOffset : hashOffset+HASH_BYTES]
}
