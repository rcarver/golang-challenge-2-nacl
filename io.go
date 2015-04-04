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

// SecureReader implements io.Reader and uses a private/public keypair to
// decrypt messages from the underlying Reader.
type SecureReader struct {
	r    io.Reader
	pub  *[32]byte
	priv *[32]byte
}

// Read implements io.Reader. Expects that data read from the reader has been
// encrypted.
func (r *SecureReader) Read(buf []byte) (int, error) {
	out := make([]byte, maxMessageSize)

	// Read everything into the buffer.
	c, err := r.r.Read(out)
	if err != nil {
		return c, err
	}

	debugf("Read: %d bytes\n%s\n", c, hex.Dump(out[:c]))

	// Initialize the Nonce by writing from the buffer
	var nonce Nonce
	if _, err := nonce.Write(out); err != nil {
		return 0, err
	}

	// The message is the rest of what was read.
	var msg = out[len(nonce):c]

	debugf("Read: nonce\n%s\n", hex.Dump(nonce[:]))
	debugf("Read: msg\n%s\n", hex.Dump(msg))

	// Decrypt the message.
	nonceBytes := [24]byte(nonce)
	res, ok := box.Open(nil, msg, &nonceBytes, r.pub, r.priv)
	if !ok {
		return 0, errors.New("decryption failed")
	}

	debugf("Read: result\n%s\n", hex.Dump(res))

	// Copy the result into the read buffer.
	copy(buf, res)
	return len(res), nil
}

// SecureWriter implements io.Writer and encrypts with a private/public keypair
// before writing to the underlying writer.
type SecureWriter struct {
	w    io.Writer
	pub  *[32]byte
	priv *[32]byte
}

// Write implements io.Writer.
func (w *SecureWriter) Write(buf []byte) (int, error) {
	if len(buf) > maxMessageSize {
		return 0, fmt.Errorf("input is too long. Got: %d bytes, max: %d", len(buf), maxMessageSize)
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

	debugf("Write: nonce\n%s\n", hex.Dump(nonce[:]))

	// Encrypt the message to the output buffer.
	nonceBytes := [24]byte(*nonce)
	sealed := box.Seal(out, buf, &nonceBytes, w.pub, w.priv)

	debugf("Write: sealed %d bytes\n%s\n", len(sealed), hex.Dump(sealed))

	// Write the encrypted message to the writer.
	return w.w.Write(sealed)
}
