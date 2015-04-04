package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// debugging turns on extra logging.
var debugging = false

// debugf is a Printf wrapper used to output helpful debugging output. It may
// be used throughout this package for convenience.
func debugf(msg string, v ...interface{}) {
	if debugging == true {
		fmt.Printf(msg, v...)
	}
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{r: r, pub: pub, priv: priv}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{w: w, pub: pub, priv: priv}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	keySet := NewKeySet()
	if keySet == nil {
		return nil, fmt.Errorf("failed to create a KeySet")
	}

	// Connect on the network.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Initialize the client, perform key handshake and return a secure
	// connection to the server.
	c := NewClient(keySet)
	if err := c.Handshake(conn); err != nil {
		return nil, err
	}
	return c.SecureConn(conn), nil

}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	keySet := NewKeySet()
	if keySet == nil {
		return fmt.Errorf("failed to create a KeySet")
	}
	return NewServer(keySet).Serve(l)
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
