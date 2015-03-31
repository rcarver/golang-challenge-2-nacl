package main

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

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

	// The nonce is the first 24 bytes.
	var nonce [24]byte
	copy(nonce[:], buf)

	// The msg is the rest of the buffer that was read.
	var msg = buf[24:c]

	// Decrypt the message.
	res, ok := box.Open(nil, msg, &nonce, r.pub, r.priv)
	if !ok {
		return 0, errors.New("box.Open failed")
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
	nonce, err := newNonce()
	if err != nil {
		return 0, err
	}

	// Create an output buffer and initialize it with the nonce.
	out := make([]byte, 24)
	copy(out, nonce[:])

	// Encrypt the message to the output buffer.
	sealed := box.Seal(out, buf, &nonce, w.pub, w.priv)

	// Write the encrypted message to the writer.
	return w.w.Write(sealed)
}

func newNonce() ([24]byte, error) {
	var nonce [24]byte
	buf := make([]byte, 24)
	_, err := rand.Read(buf)
	if err != nil {
		return nonce, err
	}
	for i, v := range buf {
		nonce[i] = v
	}
	return nonce, nil
}
