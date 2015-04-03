package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const keySize = 32

// KeyPair is a public/private keypair
type KeyPair struct {
	pub  *[keySize]byte
	priv *[keySize]byte
}

// NewKeyPair initializes a KeyPair with strong values for the keys.
func NewKeyPair() *KeyPair {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return &KeyPair{pub, priv}
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
