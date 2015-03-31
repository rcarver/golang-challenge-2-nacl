package main

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type SecureWriter struct {
	w    io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func (w *SecureWriter) Write(buf []byte) (int, error) {
	nonce, err := newNonce()
	if err != nil {
		return 0, err
	}
	var out []byte
	sealed := box.Seal(out, buf, &nonce, w.pub, w.priv)
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
