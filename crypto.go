package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const keySize = 32

// ComputeSharedKey calculates the key that is shared between the public and
// private keys given. Internally, this uses box.Precompute, performing a
// Diffie-Hellman key exchange.
func ComputeSharedKey(pub, priv *[keySize]byte) *[keySize]byte {
	var key = new([keySize]byte)
	box.Precompute(key, pub, priv)
	return key
}

// KeySet manages all of the keys involved in public key cryptography and key
// exchange.
type KeySet struct {
	pub      *[keySize]byte
	priv     *[keySize]byte
	peersPub *[keySize]byte
}

// NewKeySet returns a new KeySet initialized a public/private key pair. The
// peer's public key is nil.
func NewKeySet() *KeySet {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return &KeySet{pub, priv, nil}
}

// Copy returns a new KeySet with the public and private key, and no peers
// public key.
func (ks *KeySet) Copy() *KeySet {
	return &KeySet{ks.pub, ks.priv, nil}
}

// Exchange performs a key exchange over the ReadWriter. It first writes the
// public key to the Writer, then sets the peer's public key by reading from
// the Reader.
func (ks *KeySet) Exchange(rw io.ReadWriter) error {

	// Send public key.
	debugf("Sending public key %v\n", ks.pub)
	if _, err := rw.Write(ks.pub[:]); err != nil {
		return err
	}

	// Receive public key from the client.
	ks.peersPub = &[keySize]byte{}
	if _, err := rw.Read(ks.peersPub[:]); err != nil {
		return err
	}
	debugf("Received peer's public key: %v\n", ks.peersPub)

	return nil
}

// PeersSharedKey returns the shared key computed with the peer's public key
// and the private key. Expects that the peer's public key is set, most
// commonly by calling Exchange.
func (ks *KeySet) PeersSharedKey() *[keySize]byte {
	return ComputeSharedKey(ks.peersPub, ks.priv)
}

const nonceSize = 24

// Nonce is the unique input for each new encryption.
type Nonce [nonceSize]byte

// NewNonce returns a new Nonce initialized with a random value.
func NewNonce() *Nonce {
	var nonce Nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil
	}
	return &nonce
}

// NonceFrom returns a new Nonce initialized by reading from the buffer.
// If the buffer is bigger than 24 bytes, only the first 24 bytes are read.
// An error is returned if fewer than 24 bytes are read.
func NonceFrom(buf []byte) (*Nonce, error) {
	var n Nonce
	c := copy(n[:], buf)
	if c < nonceSize {
		return nil, fmt.Errorf("did not write the entire value (wrote %d)", c)
	}
	return &n, nil
}
