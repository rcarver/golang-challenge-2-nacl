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
			if err := s.handleClient(conn); err != nil {
				s.info("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handleClient is the main handler for client/server behavior.
func (s *Server) handleClient(conn io.ReadWriter) error {
	// Send public key to the client.
	s.info("Sending public key...\n")
	if _, err := conn.Write(s.keyPair.pub[:]); err != nil {
		return err
	}

	// Read input from the client.
	s.info("Reading...\n")
	buf := make([]byte, 2048)
	c, err := conn.Read(buf)
	if err != nil {
		return err
	}
	s.info("Read %d bytes\n", c)

	// Echo it back unmodified.
	s.info("Writing...\n")
	c, err = conn.Write(buf[:c])
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
	keyPair     *KeyPair
	peersPubKey *[32]byte
	logger      *log.Logger
}

// NewClient initializes a Client with the private key. Its public key
// will be retrieved from the server.
func NewClient(keyPair *KeyPair) *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{keyPair: keyPair, logger: logger}
}

// Handshake retrieves the public key from the server.
func (c *Client) Handshake(conn io.Reader) error {
	// Receive private key from the server.
	c.info("Receiving public key...\n")
	c.peersPubKey = &[32]byte{}
	if _, err := conn.Read(c.peersPubKey[:]); err != nil {
		return err
	}
	c.info("Received public key: %v\n", c.peersPubKey)
	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that a peer's public key has been provided, probably by reading it
// via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.keyPair.priv, c.keyPair.pub)
	w := NewSecureWriter(conn, c.keyPair.priv, c.keyPair.pub)
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
