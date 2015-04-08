package main

import (
	"encoding/binary"
	"io"
	"testing"
)

func Test_SecureWriter_Read_fails(t *testing.T) {
	key := &[32]byte{}
	r, w := io.Pipe()
	sr := SecureReader{r, key}

	in := make([]byte, 100)
	binary.BigEndian.PutUint64(in, 30)
	copy(in[8:], []byte{'a', 'b', 'c', 'd'})
	go w.Write(in)

	var out = make([]byte, 1024)
	c, err := sr.Read(out)

	if c != 0 {
		t.Fatalf("Want 0 bytes")
	}
	if err == nil {
		t.Fatalf("Want error")
	}
	if err.Error() != "decryption failed" {
		t.Fatalf("Got error: %s, want 'decryption failed'", err)
	}
}

func Test_SecureWriter_Write(t *testing.T) {
	r, w := io.Pipe()
	sw := SecureWriter{w, &[32]byte{}}

	var readBytes int
	var out = make([]byte, maxMessageSize+1024)
	go func() {
		readBytes, _ = io.ReadFull(r, out)
	}()

	buf := make([]byte, maxMessageSize)
	writtenBytes, err := sw.Write(buf[:])
	if err != nil {
		t.Fatalf("Got error %s, want no error", err)
	}
	if uint64(writtenBytes) != maxWrittenMessageSize {
		t.Fatalf("Got %d bytes written, want to write %d", writtenBytes, maxWrittenMessageSize)
	}

	headerSize := uint64(8)
	messageSize := binary.BigEndian.Uint64(out)

	if want := messageSize + headerSize; want != uint64(writtenBytes) {
		t.Fatalf("Want the right size result, got %d, want %d", writtenBytes, want)
	}
	if got := out[messageSize+headerSize-1]; got == 0 {
		t.Fatalf("Got %#v, want non-zero at the end of the data", got)
	}
	if got := out[messageSize+headerSize]; got != 0 {
		t.Fatalf("Got %#v, want zero past the data", got)
	}
}

func Test_SecureWriter_Write_TooLong(t *testing.T) {
	key := &[32]byte{}
	buf := [maxMessageSize + 1]byte{}

	_, w := io.Pipe()
	sw := SecureWriter{w, key}

	c, err := sw.Write(buf[:])
	if err == nil {
		t.Fatalf("Want an error")
	}
	if c != 0 {
		t.Fatalf("Got %d bytes written, want 0 bytes written", c)
	}

}

func Test_Secure_ReadWrite(t *testing.T) {
	key := &[32]byte{}
	buf := [4]byte{'a', 'b', 'c', 'd'}

	r, w := io.Pipe()
	sr := SecureReader{r, key}
	sw := SecureWriter{w, key}

	var out = make([]byte, 1024)
	var readBytes = -1
	go func() {
		var err error
		readBytes, err = sr.Read(out)
		if err != nil {
			t.Fatalf("Got error %s, want no error", err)
		}
	}()

	_, err := sw.Write(buf[:])
	if err != nil {
		t.Fatalf("Got error %s, want no error", err)
	}

	if readBytes != 4 {
		t.Fatalf("Got %d bytes read, want 4 bytes", readBytes)
	}
	if string(out[:4]) != "abcd" {
		t.Fatalf("Got %s, want abcd", out)
	}
}
