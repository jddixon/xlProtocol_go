# xlProtocol_go

The Go language protocol library for XLattice.  The library includes

* **tlv16**, code supporting the classic *Type-Length-Value* fields
found in many network protocols.
* **chunks**, a protocol used for intermixing large blocks of raw data
with Protocol Buffer messages
* **aes_cnx**, a protocol for establishing AES communications sessions

## aes_cnx

This protocol is used by XLattice nodes for setting up communications
sessions with Peers or other
[XLattice Nodes](https://jddixon.github.io/xlNode_go)
where the initiating Node knows the public RSA key associated with an
address.

* the initiator selects a temporary 256-bit/32-byte AES session key,
  encrypts it using the respondent's RSA public key and
  [RSA OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding),
  and sends the result to the Peer
* the server chooses the actual 32-byte AES session key, encrypts that using
  the temporary AES key, and sends this back to the initiator
* the initiator uses the temporary AES key to decrypt the response, and
  extracts the real AES session key
* the session continues with both sides using the real session key

The Nodes involved, the initiator and the respondent, may use any mutually
agreeable protocol to continue the session.  That may include a procedure
for changing the session key, as is prudent in any longer-term session.
It is probably prudent to change the session key at least once an hour if
there are significant levels of traffic on the link.

## Chunks

Chunks is a message protocol designed to be intermixed with Protobuf
[(Google's Protocol Buffer)](http://code.google.com/p/protobuf/) messages.
For more information click
[here](chunks.html)

## Project Status

The `tlv16`, `aes_cnx`, and `chunks` packages are **stable and well-tested**.

The `aes_cnx` package has been in use since mid-2014 in its present form.

`chunks` has not yet been used in production.

## On-line Documentation

More information on the **xlProtocol_go** project can be found
[here](://jddixon.github.io/xlProtocol_go)
