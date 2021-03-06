package chunks

// xlProtocol_go/chunks/chunkListAssyDisassy_test.go

import (
	"bytes"
	//"github.com/golang/x/crypto/sha3"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xi "github.com/jddixon/xlNodeID_go"
	u "github.com/jddixon/xlU_go"
	xu "github.com/jddixon/xlUtil_go"
	xf "github.com/jddixon/xlUtil_go/lfs"
	. "gopkg.in/check.v1"
	"os"
	"path"
	"time"
)

var _ = fmt.Print

func (s *XLSuite) TestChunkListAssyDisassy(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_CHUNK_LIST_ASSY_DISASSY")
	}
	rng := xr.MakeSimpleRNG()

	// make a slice 3 to 7 chunks long, fill with random-ish data ---
	chunkCount := 3 + rng.Intn(5) // so 3 to 7, inclusive
	lastChunkLen := 1 + rng.Intn(MAX_DATA_BYTES-1)
	dataLen := (chunkCount-1)*MAX_DATA_BYTES + lastChunkLen
	data := make([]byte, dataLen)
	rng.NextBytes(data)

	// calculate datum, the SHA hash of the data --------------------
	//d := sha3.NewKeccak256()
	d := sha1.New()
	d.Write(data)
	hash := d.Sum(nil)
	datum, err := xi.NewNodeID(hash)
	c.Assert(err, IsNil)

	// create tmp if it doesn't exist -------------------------------
	found, err := xf.PathExists("tmp")
	c.Assert(err, IsNil)
	if !found {
		err = os.MkdirAll("tmp", 0755)
		c.Assert(err, IsNil)
	}

	// create scratch subdir with unique name -----------------------
	var pathToU string
	for {
		dirName := rng.NextFileName(8)
		pathToU = path.Join("tmp", dirName)
		found, err = xf.PathExists(pathToU)
		c.Assert(err, IsNil)
		if !found {
			break
		}
	}

	// create a FLAT uDir at that point -----------------------------
	myU, err := u.New(pathToU, u.DIR_FLAT, 0) // 0 means default perm
	c.Assert(err, IsNil)

	// write the test data into uDir --------------------------------
	bytesWritten, key, err := myU.PutData(data, datum.Value())
	c.Assert(err, IsNil)
	c.Assert(bytes.Equal(datum.Value(), key), Equals, true)
	c.Assert(bytesWritten, Equals, int64(dataLen))

	skPriv, err := rsa.GenerateKey(rand.Reader, 1024) // cheap key
	sk := &skPriv.PublicKey
	c.Assert(err, IsNil)
	c.Assert(skPriv, NotNil)

	// Verify the file is present in uDir ---------------------------
	// (yes this is a test of uDir logic but these are early days ---
	// XXX uDir.Exist(arg) - arg should be []byte, no string
	keyStr := hex.EncodeToString(key)
	found, err = myU.HexKeyExists(keyStr)
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)

	// use the data file to build a chunkList, writing the chunks ---
	title := rng.NextFileName(8)
	now := xu.Timestamp(time.Now().UnixNano())

	// make a reader --------------------------------------
	pathToData, err := myU.GetPathForHexKey(keyStr)
	c.Assert(err, IsNil)
	reader, err := os.Open(pathToData) // open for read only
	c.Assert(err, IsNil)
	defer reader.Close()

	chunkList, err := NewChunkList(sk, title, now, reader, int64(dataLen), key, myU)
	c.Assert(err, IsNil)
	err = chunkList.Sign(skPriv)
	c.Assert(err, IsNil)

	digSig, err := chunkList.GetDigSig()
	c.Assert(err, IsNil)
	c.Assert(bytes.Equal(digSig, chunkList.digSig), Equals, true)

	err = chunkList.Verify()
	c.Assert(err, IsNil)

	// REBUILD AND CHECK --------------------------------------------
	// rebuild the complete file from the chunkList and files present
	// in myU

	u2, err := u.New(pathToU, u.DIR_FLAT, 0) // 0 means default perm
	c.Assert(err, IsNil)

	var data2 []byte // should become copy of original
	count := chunkList.Size()
	for i := uint(0); i < count; i++ {
		chunkHash, err := chunkList.HashItem(i)
		c.Assert(err, IsNil)
		c.Assert(chunkHash, NotNil)
		var raw []byte
		// THIS IS A CHUNK, and so has a header, possibly some
		// padding, and then its own hash :-).  Need to verify
		// and discard the last, then drop the padding.
		// CORRECTION: hash should NOT have been written to disk
		raw, err = u2.GetData(chunkHash)
		c.Assert(err, IsNil)

		chunk := &Chunk{packet: raw}
		ndx := chunk.GetIndex()
		c.Assert(ndx, Equals, uint32(i))
		rawLen := uint32(len(raw))
		dataLen := chunk.GetDataLen()

		//fmt.Printf("chunk %2d: index is %8d\n", i, ndx)
		//fmt.Printf("          len raw is %6d (%4x)\n", rawLen, rawLen)
		//fmt.Printf("          dataLen is %6d (%4x)\n", dataLen, dataLen)

		// if this isn't true, we get a panic
		c.Assert(dataLen < rawLen, Equals, true)
		payload := chunk.GetData()

		data2 = append(data2, payload...)
	}
	// verify that the content key of the rebuilt file is identical to
	// that of the original

	//d2D := sha3.NewKeccak256()
	d2D := sha1.New()
	d2D.Write(data2)
	hash2 := d2D.Sum(nil)
	datum2, err := xi.NewNodeID(hash2)
	c.Assert(err, IsNil)
	// DEBUG
	//fmt.Printf("datum:  %x\ndatum2: %x\n", datum.Value(), datum2.Value())
	//fmt.Printf("data: %x\ndata2: %x\n", data, data2)
	// END
	c.Assert(bytes.Equal(datum.Value(), datum2.Value()), Equals, true)

	// presumably pure pedantry: verify that the file contents are
	// also equal

	c.Assert(bytes.Equal(data, data2), Equals, true)
}
