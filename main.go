package main

import (
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

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	// Generate private key.
	priv, err := NewKey()
	if err != nil {
		return nil, err
	}

	// Connect on the network.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Initialize the client, perform key handshake and return
	// a piped connection to the server.
	c := NewClient(priv)
	if err := c.ReadPublicKey(conn); err != nil {
		return nil, err
	}
	return c.SecureConn(conn), nil

}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	// Generate public key.
	pub, err := NewKey()
	if err != nil {
		return err
	}
	return NewServer(pub).Serve(l)
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
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
