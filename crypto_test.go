package main

import (
	"bytes"
	"io"
	"testing"
)

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

func Test_KeySet_PeersKeyPair(t *testing.T) {
	ks := &KeySet{
		&[32]byte{'a'},
		&[32]byte{'b'},
		&[32]byte{'c'},
	}
	pub, priv := ks.PeersKeyPair()
	if want := []byte("c"); !bytes.Equal(want, pub[:1]) {
		t.Fatalf("pub want %s, got %s", want, pub[:1])
	}
	if want := []byte("b"); !bytes.Equal(want, priv[:1]) {
		t.Fatalf("priv want %s, got %s", want, priv[:1])
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

func Test_Nonce_Read(t *testing.T) {
	n := Nonce{'a'}

	var buf = make([]byte, len(n))
	c, err := n.Read(buf)

	if err != nil {
		t.Fatalf("want no error, got %s", err)
	}
	if got := c; got != 24 {
		t.Fatalf("want 24 bytes read, got %d", got)
	}
	if buf[0] != 'a' {
		t.Fatalf("want buffer to have value of nonce, got %s", buf)
	}
}

func Test_Nonce_Read_fail(t *testing.T) {
	n := Nonce{'a'}

	var buf = make([]byte, len(n)-1)
	c, err := n.Read(buf)

	if err == nil {
		t.Fatalf("want error")
	}
	if got := c; got != 23 {
		t.Fatalf("want 23 bytes read, got %d", got)
	}
}

func Test_Nonce_Write(t *testing.T) {
	n := Nonce{}
	buf := make([]byte, len(n))

	copy(buf, "hello")
	c, err := n.Write(buf)

	if err != nil {
		t.Fatalf("want no error, got %s", err)
	}
	if got := c; got != 24 {
		t.Fatalf("want 24 bytes written, got %d", got)
	}

	a := make([]byte, len(n))
	copy(a, "hello")
	if !bytes.Equal(a, n[:]) {
		t.Fatalf("want nonce to have value of buffer, got %s", n)
	}
}

func Test_Nonce_Write_fail(t *testing.T) {
	n := Nonce{}
	buf := make([]byte, len(n)-1)

	c, err := n.Write(buf)

	if err == nil {
		t.Fatalf("want error")
	}
	if got := c; got != 23 {
		t.Fatalf("want 23 bytes written, got %d", got)
	}
}
