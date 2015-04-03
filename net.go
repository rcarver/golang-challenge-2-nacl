package main

import (
	"io"
	"log"
	"net"
	"os"
)

// Server is the encrypted echo server.
type Server struct {
	keyPair *KeyPair
	logger  *log.Logger
}

// NewServer initializes a new Server with the key pair.
func NewServer(keyPair *KeyPair) *Server {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	return &Server{keyPair: keyPair, logger: logger}
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
			if err := s.handshake(conn); err != nil {
				s.info("Error performing handshake client: %s", err)
			}
			if err := s.handle(conn); err != nil {
				s.info("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key swap with the client.
func (s *Server) handshake(conn io.ReadWriter) error {
	// Send public key to the client.
	s.info("Sending public key...\n")
	if _, err := conn.Write(s.keyPair.pub[:]); err != nil {
		return err
	}

	// Send private key to the client.
	s.info("Sending private key...\n")
	if _, err := conn.Write(s.keyPair.priv[:]); err != nil {
		return err
	}

	return nil
}

// handle is the main handler for client/server behavior.
func (s *Server) handle(conn io.ReadWriter) error {

	sr := NewSecureReader(conn, s.keyPair.pub, s.keyPair.priv)
	sw := NewSecureWriter(conn, s.keyPair.pub, s.keyPair.priv)

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
	keyPair *KeyPair
	logger  *log.Logger
}

// NewClient initializes a Client with the private key. Its public key
// will be retrieved from the server.
func NewClient() *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{keyPair: &KeyPair{}, logger: logger}
}

// Handshake retrieves the public key from the server.
func (c *Client) Handshake(conn io.ReadWriter) error {

	// Receive public key from the server.
	c.keyPair.pub = &[32]byte{}
	if _, err := conn.Read(c.keyPair.pub[:]); err != nil {
		return err
	}
	c.info("Received public key: %v\n", c.keyPair.pub)

	// Receive private key from the server.
	c.keyPair.priv = &[32]byte{}
	if _, err := conn.Read(c.keyPair.priv[:]); err != nil {
		return err
	}
	c.info("Received private key: %v\n", c.keyPair.priv)

	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that a peer's public key has been provided, probably by reading it
// via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.keyPair.pub, c.keyPair.priv)
	w := NewSecureWriter(conn, c.keyPair.pub, c.keyPair.priv)
	return &rwc{r, w, conn}
}

func (c *Client) info(str string, v ...interface{}) {
	if c.logger != nil {
		c.logger.Printf(str, v...)
	}
}

// rwc implements io.ReadWriteCloser with an object for each role.
type rwc struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (io *rwc) Read(buf []byte) (int, error) {
	return io.r.Read(buf)
}

func (io *rwc) Write(buf []byte) (int, error) {
	return io.w.Write(buf)
}

func (io *rwc) Close() error {
	return io.c.Close()
}
