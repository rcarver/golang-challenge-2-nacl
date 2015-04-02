package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const keySize = 32

// NewKey returns a byte array with a random value, to be used as a crypto key.
func NewKey() (*[keySize]byte, error) {
	var key [keySize]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return &key, err
	}
	return &key, nil
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
		return c, errors.New(fmt.Sprintf("did not read the entire value (read %d)", c))
	}
	return c, nil
}

// Write sets the nonce value by reading the buffer.
func (n *Nonce) Write(buf []byte) (int, error) {
	c := copy(n[:], buf)
	if c < nonceSize {
		return c, errors.New(fmt.Sprintf("did not write the entire value (wrote %d)", c))
	}
	return c, nil
}

// Array returns a byte array of the nonce value.
// NOTE: this shouldn't be necessary but I can't figure out how to cast Nonce to *[24]byte.
func (n *Nonce) Array() *[nonceSize]byte {
	var b [nonceSize]byte
	for i, x := range n {
		b[i] = x
	}
	return &b
}
