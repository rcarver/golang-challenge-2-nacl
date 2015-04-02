package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// maxMessageSize is the greatest number of bytes that can be transmitted
// as a single message using SecureReader and SecureWriter.
var maxMessageSize = 3072

type SecureReader struct {
	r    io.Reader
	priv *[32]byte
	pub  *[32]byte
}

func (r *SecureReader) Read(buf []byte) (int, error) {
	out := make([]byte, maxMessageSize)

	// Read everything into the buffer.
	c, err := r.r.Read(out)
	if err != nil {
		return c, err
	}

	fmt.Printf("Read: all (len %d)\n%s\n", c, hex.Dump(out[:c]))

	// Initialize the Nonce by writing from the buffer
	var nonce Nonce
	if _, err := nonce.Write(out); err != nil {
		return 0, err
	}

	// The message is the rest of what was read.
	var msg = out[len(nonce):c]

	fmt.Printf("Read: nonce\n%s\n", hex.Dump(nonce[:]))
	fmt.Printf("Read: msg\n%s\n", hex.Dump(msg))

	// Decrypt the message.
	nonceBytes := [24]byte(nonce)
	res, ok := box.Open(nil, msg, &nonceBytes, r.pub, r.priv)
	if !ok {
		return 0, errors.New("decryption failed")
	}

	fmt.Printf("Read: result\n%s\n", hex.Dump(res))

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
	if len(buf) > maxMessageSize {
		return 0, errors.New(fmt.Sprintf("input is too long. Got: %d bytes, max: %d", len(buf), maxMessageSize))
	}

	// Create a nonce.
	nonce := NewNonce()
	if nonce == nil {
		return 0, errors.New("failed to create nonce")
	}

	// Create an output buffer and initialize it with the nonce.
	out := make([]byte, len(nonce))
	if _, err := nonce.Read(out); err != nil {
		return 0, err
	}

	fmt.Printf("Write: nonce\n%s\n", hex.Dump(nonce[:]))

	// Encrypt the message to the output buffer.
	nonceBytes := [24]byte(*nonce)
	sealed := box.Seal(out, buf, &nonceBytes, w.pub, w.priv)

	fmt.Printf("Write: sealed\n%s\n", hex.Dump(sealed))

	// Write the encrypted message to the writer.
	return w.w.Write(sealed)
}
