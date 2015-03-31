package main

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// Nonce is the unique input for each new encryption. This type implements
// io.Reader and io.Writer to easily move the byte value around.
type Nonce [nonceSize]byte

const nonceSize = 24

// newNonce returns a new Nonce with a random value.
func newNonce() *Nonce {
	var nonce Nonce
	buf := make([]byte, nonceSize)
	_, err := rand.Read(buf)
	if err != nil {
		return nil
	}
	for i, v := range buf {
		nonce[i] = v
	}
	return &nonce
}

// Read puts the nonce value into the buffer.
func (n *Nonce) Read(buf []byte) (int, error) {
	c := copy(buf, n[:])
	if c < nonceSize {
		return c, errors.New("did not read the entire value")
	}
	return c, nil
}

// Write sets the nonce value by reading the buffer.
func (n *Nonce) Write(buf []byte) (int, error) {
	c := copy(n[:], buf)
	if c < nonceSize {
		return c, errors.New("did not write the entire value")
	}
	return c, nil
}

// Array returns a byte array of the nonce value.
func (n *Nonce) Array() *[nonceSize]byte {
	var b [nonceSize]byte
	for i, x := range n {
		b[i] = x
	}
	return &b
}

type SecureReader struct {
	r    io.Reader
	priv *[32]byte
	pub  *[32]byte
}

func (r *SecureReader) Read(buf []byte) (int, error) {
	// Read everything into the buffer.
	c, err := r.r.Read(buf)
	if err != nil {
		return c, err
	}

	//fmt.Printf("Read: buf\n%s\n", hex.Dump(buf))

	// Initialize the Nonce by reading from the buffer
	var nonce Nonce
	if _, err := nonce.Write(buf); err != nil {
		return 0, err
	}

	// The message is the rest of what was read.
	var msg = buf[len(nonce):c]

	//fmt.Printf("Read: nonce\n%s\n", hex.Dump(nonce.Array()[:]))
	//fmt.Printf("Read: msg\n%s\n", hex.Dump(msg))

	// Decrypt the message.
	res, ok := box.Open(nil, msg, nonce.Array(), r.pub, r.priv)
	if !ok {
		return 0, errors.New("decryption failed")
	}

	// Copy the result into the read buffer.
	copy(buf, res)
	return len(res), nil
}

type SecureWriter struct {
	w    io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func (w *SecureWriter) Write(buf []byte) (int, error) {
	// Create a nonce.
	nonce := newNonce()
	if nonce == nil {
		return 0, errors.New("failed to create nonce")
	}

	// Create an output buffer and initialize it with the nonce.
	out := make([]byte, len(nonce))
	if _, err := nonce.Read(out); err != nil {
		return 0, err
	}

	//fmt.Printf("Write: nonce\n%s\n", hex.Dump(nonce.Array()[:]))

	// Encrypt the message to the output buffer.
	sealed := box.Seal(out, buf, nonce.Array(), w.pub, w.priv)

	//fmt.Printf("Write: sealed\n%s\n", hex.Dump(sealed))

	// Write the encrypted message to the writer.
	return w.w.Write(sealed)
}
