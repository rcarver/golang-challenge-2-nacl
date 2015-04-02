package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{r, priv, pub}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{w, priv, pub}
}

type RW struct {
	r io.Reader
	w io.Writer
	c net.Conn
}

func (rw *RW) Read(buf []byte) (int, error) {
	return rw.r.Read(buf)
}

func (rw *RW) Write(buf []byte) (int, error) {
	return rw.w.Write(buf)
}

func (rw *RW) Close() error {
	return rw.c.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Send private key to the server.
	logger.Printf("Sending private key...\n")
	priv := &[32]byte{'p', 'r', 'i', 'v', '!'}
	if _, err = conn.Write(priv[:]); err != nil {
		return nil, err
	}

	// Receive private key from the server.
	logger.Printf("Receiving public key...\n")
	pub := &[32]byte{}
	if _, err = conn.Read(pub[:]); err != nil {
		return nil, err
	}

	logger.Printf("priv key: %s\n", priv)
	logger.Printf("pub key: %s\n", pub)

	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)

	return &RW{r, w, conn}, nil

}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		// Send public key to the client.
		logger.Printf("Sending public key...\n")
		pub := &[32]byte{'p', 'u', 'b', '!'}
		if _, err := conn.Write(pub[:]); err != nil {
			return err
		}
		// Receive private key from the client.
		logger.Printf("Receiving private key...\n")
		priv := &[32]byte{}
		if _, err = conn.Read(priv[:]); err != nil {
			return err
		}

		logger.Printf("priv key: %s\n", priv)
		logger.Printf("pub key: %s\n", pub)

		logger.Printf("Reading...\n")
		buf := make([]byte, 2048)
		c, err := conn.Read(buf)
		if err != nil {
			return err
		}
		logger.Printf("Read: %d\n%s\n", c, hex.Dump(buf[:c]))

		logger.Printf("Writing...\n")
		c, err = conn.Write(buf[:c])
		if err != nil {
			return err
		}
		logger.Printf("Wrote %d\n", c)
	}
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial(fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Writing...\n")
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Reading...\n")
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Read: %s\n", buf[:n])
	fmt.Printf("%s\n", buf[:n])
}
