package main

import (
	"io"
	"log"
	"net"
	"os"
)

// Server is the encrypted echo server.
type Server struct {
	pub    *[32]byte
	logger *log.Logger
}

// NewServer initializes a new Server with the public key.
func NewServer(pub *[32]byte) *Server {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	return &Server{pub, logger}
}

// Serve starts an infinite loop waiting for client connections.
func (s *Server) Serve(l net.Listener) error {
	conns := s.acceptClients(l)
	for {
		go func() {
			conn := <-conns
			defer conn.Close()
			if err := s.handleClient(conn); err != nil {
				s.info("Error handling client: %s", err)
			}
		}()
	}
}

// handleClient is the main handler for client/server behavior.
func (s *Server) handleClient(conn net.Conn) error {
	// Send public key to the client.
	s.info("Sending public key...\n")
	if _, err := conn.Write(s.pub[:]); err != nil {
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

// acceptClients pushes new client connections to a channel.
func (s *Server) acceptClients(l net.Listener) chan net.Conn {
	ch := make(chan net.Conn)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				s.info("Failed to accept client: %s", err)
				return
			}
			ch <- conn
		}
	}()
	return ch
}

func (s *Server) info(str string, v ...interface{}) {
	s.logger.Printf(str, v...)
}

// Client is the secure echo client.
type Client struct {
	priv   *[32]byte
	pub    *[32]byte
	logger *log.Logger
}

// NewClient initializes a Client with the private key. Its public key
// will be retrieved from the server.
func NewClient(priv *[32]byte) *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{priv: priv, logger: logger}
}

// GetPublicKey retrieves the public key from the server.
func (c *Client) ReadPublicKey(conn net.Conn) error {
	// Receive private key from the server.
	c.info("Receiving public key...\n")
	c.pub = &[32]byte{}
	if _, err := conn.Read(c.pub[:]); err != nil {
		return err
	}
	c.info("Received public key: %v\n", c.pub)
	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that a public key has been provided, probably by reading it via
// ReadPublicKey.
func (c *Client) SecureConn(conn net.Conn) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.priv, c.pub)
	w := NewSecureWriter(conn, c.priv, c.pub)
	return &connIO{r, w, conn}
}

type connIO struct {
	r io.Reader
	w io.Writer
	c net.Conn
}

func (rw *connIO) Read(buf []byte) (int, error) {
	return rw.r.Read(buf)
}

func (rw *connIO) Write(buf []byte) (int, error) {
	return rw.w.Write(buf)
}

func (rw *connIO) Close() error {
	return rw.c.Close()
}

func (c *Client) info(str string, v ...interface{}) {
	c.logger.Printf(str, v...)
}
