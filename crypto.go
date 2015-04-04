package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const keySize = 32

// KeySet manages all of the keys involved in public key cryptology and key
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

// PeersKeyPair returns the public/private keys from the peer. Assumes that
// Exchange has been called in order to set the peer's public key.
func (ks *KeySet) PeersKeyPair() (*[keySize]byte, *[keySize]byte) {
	return ks.peersPub, ks.priv
}

const nonceSize = 24

// Nonce is the unique input for each new encryption. This type implements
// io.Reader and io.Writer to easily move the byte value around.
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

// Read puts the nonce value into the buffer.
func (n *Nonce) Read(buf []byte) (int, error) {
	c := copy(buf, n[:])
	if c < nonceSize {
		return c, fmt.Errorf("did not read the entire value (read %d)", c)
	}
	return c, nil
}

// Write sets the nonce value by reading the buffer.
func (n *Nonce) Write(buf []byte) (int, error) {
	c := copy(n[:], buf)
	if c < nonceSize {
		return c, fmt.Errorf("did not write the entire value (wrote %d)", c)
	}
	return c, nil
}
