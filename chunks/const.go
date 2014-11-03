package chunks

// xlProtocol_go/chunks/const.go

import (
	xc "github.com/jddixon/xlCrypto_go"
)

const (
	INDENT = "  "

	MAGIC           = 0
	MAGIC_BYTES     = 1
	MAGIC_OFFSET    = 0
	TYPE            = 0
	TYPE_BYTES      = 1
	TYPE_OFFSET     = MAGIC_OFFSET + MAGIC_BYTES
	RESERVED_OFFSET = TYPE_OFFSET + TYPE_BYTES
	RESERVED_BYTES  = 6
	// The length and index are big-endian.
	LENGTH_OFFSET = RESERVED_OFFSET + RESERVED_BYTES
	LENGTH_BYTES  = 4
	INDEX_OFFSET  = LENGTH_OFFSET + LENGTH_BYTES
	INDEX_BYTES   = 4
	DATUM_OFFSET  = INDEX_OFFSET + INDEX_BYTES
	DATUM_BYTES   = 20	// XXX was 32
	DATUM_PADDING = 12
	DATA_OFFSET   = DATUM_OFFSET + DATUM_BYTES + DATUM_PADDING
	HEADER_BYTES  = DATA_OFFSET

	HASH_BYTES = xc.SHA1_LEN
	WORD_BYTES = 16 // we pad to likely cpu cache size in bytes

	// 2014-03-11 CHANGE: this is now construed as the maximum size of the
	// entire packet, including the header and the terminating chunk hash.
	//MAX_CHUNK_BYTES = 128 * 1024 // 128 KB

	// 2014-10-09 experiment
	MAX_CHUNK_BYTES = 128 * 1024 // 128 KB

	MAX_DATA_BYTES = MAX_CHUNK_BYTES - (HEADER_BYTES + HASH_BYTES)
)

