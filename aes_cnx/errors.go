package aes_cnx

import (
	e "errors"
)

var (
	NilConnection = e.New("nil connection argument")
	NilNode       = e.New("nil node argument")
	WrongOAEPSize = e.New("decrypted OAEP packet size wrong")
)
