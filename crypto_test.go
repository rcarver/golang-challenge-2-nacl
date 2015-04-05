package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func Test_ComputeSharedKey(t *testing.T) {
	aPub, aPriv, _ := box.GenerateKey(rand.Reader)
	bPub, bPriv, _ := box.GenerateKey(rand.Reader)
	aShare := ComputeSharedKey(bPub, aPriv)
	bShare := ComputeSharedKey(aPub, bPriv)
	if !bytes.Equal(aShare[:], bShare[:]) {
		t.Fatalf("want equal shared keys\na: %v\nb: %v", aShare, bShare)
	}
}

func Test_NewKeySet(t *testing.T) {
	k := NewKeySet()
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

func Test_KeySet_Copy(t *testing.T) {
	a := &KeySet{
		&[32]byte{'a'},
		&[32]byte{'b'},
		&[32]byte{'c'},
	}
	b := a.Copy()
	if !bytes.Equal(a.pub[:], b.pub[:]) {
		t.Fatalf("pub want %#v, got %#v", a.pub, b.pub)
	}
	if !bytes.Equal(a.priv[:], b.priv[:]) {
		t.Fatalf("priv want %#v got %#v", a.priv, b.priv)
	}
	if b.peersPub != nil {
		t.Fatalf("peersPub want nil, got %#v", b.peersPub)
	}
}

func Test_KeySet_Exchange(t *testing.T) {
	ks := &KeySet{
		&[32]byte{'a'},
		&[32]byte{'b'},
		nil,
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

	err := ks.Exchange(rw)
	if err != nil {
		t.Fatalf("want no error in Exchange")
	}
	if !bytes.Equal(ks.pub[:], w.Bytes()) {
		t.Fatalf("send key: want %#v, got %#v", ks.pub, w.Bytes())
	}
	if !bytes.Equal(peersPub[:], ks.peersPub[:]) {
		t.Fatalf("recv key: want %#v, got %#v", peersPub, ks.peersPub)
	}
}

func Test_KeySet_PeersSharedKey(t *testing.T) {
	ks := &KeySet{
		&[32]byte{'a'},
		&[32]byte{'b'},
		&[32]byte{'c'},
	}
	want := ComputeSharedKey(ks.peersPub, ks.priv)
	got := ks.PeersSharedKey()
	if !bytes.Equal(want[:], got[:]) {
		t.Fatalf("shared want %v, got %v", want, got)
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
