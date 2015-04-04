package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Server is the secure echo server.
type Server struct {
	pub    *[32]byte
	priv   *[32]byte
	logger *log.Logger
}

// NewServer initializes a new Server with the key pair.
func NewServer(pub, priv *[32]byte) *Server {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	return &Server{pub: pub, priv: priv, logger: logger}
}

// Serve starts an infinite loop waiting for client connections.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.info("Failed to accept client: %s", err)
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			peersPub, err := s.handshake(conn)
			if err != nil {
				s.info("Error performing handshake: %s", err)
			}
			if err := s.handle(conn, peersPub); err != nil {
				s.info("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key exchange with the client.
func (s *Server) handshake(conn io.ReadWriter) (*[32]byte, error) {

	// Send public key to the client.
	s.info("Sending public key %v\n", s.pub)
	if _, err := conn.Write(s.pub[:]); err != nil {
		return nil, err
	}

	// Receive public key from the client.
	peersPub := [32]byte{}
	if _, err := conn.Read(peersPub[:]); err != nil {
		return nil, err
	}
	s.info("Received peer's public key: %v\n", peersPub)

	return &peersPub, nil
}

// handle takes care of client/server behavior after the handshake.
func (s *Server) handle(conn io.ReadWriter, peersPub *[32]byte) error {

	sr := NewSecureReader(conn, s.priv, peersPub)
	sw := NewSecureWriter(conn, s.priv, peersPub)

	// Read decrypted data from the client.
	s.info("Reading...\n")
	buf := make([]byte, 2048)
	c, err := sr.Read(buf)
	if err != nil {
		return err
	}
	s.info("Read %d bytes: %s\n", c, buf[:c])

	// Write encrypted data back to the client.
	s.info("Writing...\n")
	c, err = sw.Write(buf[:c])
	if err != nil {
		return err
	}
	s.info("Wrote %d bytes\n", c)

	return nil
}

func (s *Server) info(str string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(str, v...)
	}
}

// Client is the secure echo client.
type Client struct {
	pub      *[32]byte
	priv     *[32]byte
	peersPub *[32]byte
	logger   *log.Logger
}

// NewClient initializes a Client with the private key. Its public key will be
// retrieved from the server.
func NewClient(pub, priv *[32]byte) *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{pub: pub, priv: priv, logger: logger}
}

// Handshake performs the key exchange with the server.
func (c *Client) Handshake(conn io.ReadWriter) error {

	// Receive public key from the server.
	c.peersPub = &[32]byte{}
	if _, err := conn.Read(c.peersPub[:]); err != nil {
		return fmt.Errorf("error reading: %s", err)
	}
	c.info("Received peer's public key: %v\n", c.peersPub)

	// Send public key to the server
	c.info("Sending public key %v\n", c.pub)
	if _, err := conn.Write(c.pub[:]); err != nil {
		return fmt.Errorf("error writing: %s", err)
	}

	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that the peer's public key has been provided, probably by reading it
// via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.priv, c.peersPub)
	w := NewSecureWriter(conn, c.priv, c.peersPub)
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}
}

func (c *Client) info(str string, v ...interface{}) {
	if c.logger != nil {
		c.logger.Printf(str, v...)
	}
}
