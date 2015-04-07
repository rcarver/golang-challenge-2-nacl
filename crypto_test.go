package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func Test_NewKeyPair(t *testing.T) {
	k := NewKeyPair()
	if k == nil {
		t.Fatalf("want a key, got nil")
	}
	var check = func(k *[32]byte) {
		var a = make([]byte, len(k))
		var b = make([]byte, len(k))
		copy(a, k[:])
		if bytes.Equal(a, b) {
			t.Fatalf("want non-zero value")
		}
	}
	check(k.priv)
	check(k.pub)
}

func Test_KeyPair_Exchange(t *testing.T) {
	kp := &KeyPair{
		&[32]byte{'a'},
		&[32]byte{'b'},
	}
	peersPub := [32]byte{'c'}

	// Fake a io.ReadWriter
	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	// Write the peersPub to the buffer.
	r.Write(peersPub[:])

	kp2, err := kp.Exchange(rw)
	if err != nil {
		t.Fatalf("want no error in Exchange")
	}
	if !bytes.Equal(kp.pub[:], w.Bytes()) {
		t.Fatalf("send pub key: want %#v, got %#v", kp.pub, w.Bytes())
	}
	if !bytes.Equal(kp2.pub[:], kp2.pub[:]) {
		t.Fatalf("recv pub key: want %#v, got %#v", kp2.pub, kp2.pub)
	}
	if !bytes.Equal(kp2.priv[:], kp2.priv[:]) {
		t.Fatalf("recv priv key: want %#v, got %#v", kp2.priv, kp2.priv)
	}
}

func Test_KeyPair_SharedKey(t *testing.T) {
	kp := &KeyPair{
		&[32]byte{'a'},
		&[32]byte{'b'},
	}
	want := SharedKey(kp.pub, kp.priv)
	got := kp.SharedKey()
	if !bytes.Equal(want[:], got[:]) {
		t.Fatalf("shared want %v, got %v", want, got)
	}
}

func Test_KeyPairDiffieHellmanSharedKey(t *testing.T) {
	kp1 := NewKeyPair()
	kp2 := NewKeyPair()
	var shared1 *[32]byte
	var shared2 *[32]byte
	r, w := io.Pipe()
	go func() {
		x, _ := kp2.recv(r)
		shared2 = x.SharedKey()
	}()
	kp1.send(w)
	go func() {
		x, _ := kp1.recv(r)
		shared1 = x.SharedKey()
	}()
	kp2.send(w)
	if shared1 == nil || shared2 == nil {
		t.Fatalf("shared must not be nil")
	}
	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Fatalf("want equal shared keys, got\na: %v\nb: %v\n", shared1, shared2)
	}
}

func Test_SharedKey(t *testing.T) {
	aPub, aPriv, _ := box.GenerateKey(rand.Reader)
	bPub, bPriv, _ := box.GenerateKey(rand.Reader)
	aShare := SharedKey(bPub, aPriv)
	bShare := SharedKey(aPub, bPriv)
	if !bytes.Equal(aShare[:], bShare[:]) {
		t.Fatalf("want equal shared keys\na: %v\nb: %v", aShare, bShare)
	}
}

func Test_NewNonce(t *testing.T) {
	n := NewNonce()

	if got := len(n); got != 24 {
		t.Fatalf("want 24, got %d", got)
	}

	var a = make([]byte, len(n))
	var b = make([]byte, len(n))
	copy(a, n[:])
	if bytes.Equal(a, b) {
		t.Fatalf("want non-zero value")
	}
}

func Test_NonceFrom(t *testing.T) {
	buf := make([]byte, nonceSize+1)
	copy(buf, "hello")

	n, err := NonceFrom(buf)

	if err != nil {
		t.Fatalf("want no error, got %s", err)
	}

	a := make([]byte, len(n))
	copy(a, "hello")
	if !bytes.Equal(a, n[:]) {
		t.Fatalf("want nonce to have value of buffer, got %v", n)
	}
}

func Test_Nonce_NonceFrom_fail(t *testing.T) {
	buf := make([]byte, nonceSize-1)

	n, err := NonceFrom(buf)

	if n != nil {
		t.Fatalf("want no nonce")
	}
	if err == nil {
		t.Fatalf("want error")
	}
}
