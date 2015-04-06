package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const keySize = 32

// KeyPair holds a public/private key pair, and facilitiates performing
// a Diffie-Hellman key exchange.
type KeyPair struct {
	pub  *[keySize]byte
	priv *[keySize]byte
}

// NewKeyPair returns a new KeyPair initialized with public and private keys.
func NewKeyPair() *KeyPair {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return &KeyPair{pub, priv}
}

// Exchange performs a key exchange over the ReadWriter. It first writes the
// public key to the Writer, then gets the peer's public key by reading from
// the Reader. A new KeyPair is returned containing the peer's public key and
// this private key.
func (kp *KeyPair) Exchange(rw io.ReadWriter) (*KeyPair, error) {
	newPair := &KeyPair{pub: &[keySize]byte{}, priv: kp.priv}

	// Send public key.
	debugf("Sending public key %v\n", kp.pub)
	if _, err := rw.Write(kp.pub[:]); err != nil {
		return nil, err
	}

	// Receive public key from the client.
	if _, err := rw.Read(newPair.pub[:]); err != nil {
		return nil, err
	}
	debugf("Received peer's public key: %v\n", newPair.pub)

	return newPair, nil
}

// SharedKey returns the shared key computed with the public key and the
// private key. By using Exchange, then calling SharedKey on the resulting
// KeyPair you get a key that can be used to communicate with the other side.
func (kp *KeyPair) SharedKey() *[keySize]byte {
	return SharedKey(kp.pub, kp.priv)
}

// SharedKey calculates the key that is shared between the public and
// private keys given. Internally, this uses box.Precompute, performing a
// Diffie-Hellman key exchange.
func SharedKey(pub, priv *[keySize]byte) *[keySize]byte {
	var key = new([keySize]byte)
	box.Precompute(key, pub, priv)
	return key
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
