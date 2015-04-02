package main

import (
	"bytes"
	"testing"
)

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

func Test_Nonce_Array(t *testing.T) {
	n := Nonce{'a', 'b', 'c'}
	a := [24]byte{'a', 'b', 'c'}

	if *n.Array() != a {
		t.Fatalf("want %s, got %s", n, a)
	}
}
