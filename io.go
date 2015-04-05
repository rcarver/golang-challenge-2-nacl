package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// maxMessageSize is the greatest number of bytes that can be transmitted
// as a single message using SecureReader and SecureWriter.
var maxMessageSize = uint64(3072)

// SecureReader implements io.Reader and uses a key decrypt messages from the
// underlying Reader.
type SecureReader struct {
	r   io.Reader
	key *[32]byte
}

// Read implements io.Reader. Expects that data read from the reader has been
// encrypted.
func (r *SecureReader) Read(buf []byte) (int, error) {
	// Read the header to find out how big the message is.
	var size uint64
	err := binary.Read(r.r, binary.BigEndian, &size)
	if err != nil {
		return 0, err
	}
	if size > maxMessageSize {
		return 0, fmt.Errorf("message is too long. max: %d, got: %d", maxMessageSize, size)
	}
	debugf("Read: %d byte message", size)

	// Read everything into the buffer.
	out := make([]byte, size)
	c, err := io.ReadFull(r.r, out)
	if err != nil {
		return 0, err
	}
	debugf("Read: %d bytes\n%s\n", c, hex.Dump(out))

	// Initialize the Nonce by writing from the buffer
	var nonce Nonce
	if _, err := nonce.Write(out); err != nil {
		return 0, err
	}

	// The message is the rest of what was read.
	var msg = out[len(nonce):]

	debugf("Read: nonce\n%s\n", hex.Dump(nonce[:]))
	debugf("Read: msg\n%s\n", hex.Dump(msg))

	// Decrypt the message.
	nonceBytes := [24]byte(nonce)
	res, ok := box.OpenAfterPrecomputation(nil, msg, &nonceBytes, r.key)
	if !ok {
		return 0, errors.New("decryption failed")
	}

	debugf("Read: result\n%s\n", hex.Dump(res))

	// Copy the result into the read buffer.
	copy(buf, res)
	return len(res), nil
}

// SecureWriter implements io.Writer and encrypts data with a key before
// writing to the underlying writer.
type SecureWriter struct {
	w   io.Writer
	key *[32]byte
}

// Write implements io.Writer.
func (w *SecureWriter) Write(buf []byte) (int, error) {
	if uint64(len(buf)) > maxMessageSize {
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
	sealed := box.SealAfterPrecomputation(out, buf, &nonceBytes, w.key)

	debugf("Write: sealed %d bytes\n%s\n", len(sealed), hex.Dump(sealed))

	// Write a fixed header indicating how long the message is.
	header := uint64(len(sealed))
	headerSize := binary.Size(header)
	if err := binary.Write(w.w, binary.BigEndian, header); err != nil {
		return headerSize, err
	}
	// Write the message.
	messageSize, err := w.w.Write(sealed)
	// Return the size of the header and the message.
	return headerSize + messageSize, err
}
