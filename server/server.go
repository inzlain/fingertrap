// Example server using yamux for multiplexing
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
)

func main() {
	listenAddr := flag.String("listen", ":2222", "Address for SSH clients to connect to")
	tunnelAddr := flag.String("tunnel", ":9000", "Address for fingertrap clients to connect to")
	certFile := flag.String("cert", "server.crt", "Path to TLS certificate file")
	keyFile := flag.String("key", "server.key", "Path to TLS key file")
	flag.Parse()

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate and key: %v", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	log.Printf("TLS enabled with certificate from %s", *certFile)

	// Create a custom ListenConfig with SO_REUSEADDR enabled
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	// Listen for tunnel client
	tunnelListener, err := lc.Listen(context.Background(), "tcp", *tunnelAddr)
	if err != nil {
		log.Fatalf("Failed to listen for tunnel on %s: %v", *tunnelAddr, err)
	}
	defer tunnelListener.Close()
	
	// Wrap with TLS
	tunnelListener = tls.NewListener(tunnelListener, tlsConfig)
	log.Printf("Waiting for secure tunnel client connections on %s", *tunnelAddr)

	// To track and synchronise port release
	var portMutex sync.Mutex
	var clientListener net.Listener
	var clientListenerClosed bool

	for {
		// Accept connection from tunnel client
		tunnelConn, err := tunnelListener.Accept()
		if err != nil {
			log.Printf("Failed to accept tunnel connection: %v", err)
			continue
		}

		// Get remote address before we might lose connection
		remoteAddr := tunnelConn.RemoteAddr().String()
		log.Printf("Secure tunnel client connected from %s", remoteAddr)

		// Apply TCP optimizations
		if tcpConn, ok := tunnelConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(60 * time.Second)
			tcpConn.SetReadBuffer(256 * 1024)
			tcpConn.SetWriteBuffer(256 * 1024)
		}

		// Setup yamux server with optimizations
		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		config.AcceptBacklog = 256
		config.MaxStreamWindowSize = 512 * 1024
		config.StreamOpenTimeout = 30 * time.Second
		config.ConnectionWriteTimeout = 10 * time.Second
		config.KeepAliveInterval = 30 * time.Second
		config.EnableKeepAlive = true
		session, err := yamux.Server(tunnelConn, config)
		if err != nil {
			log.Printf("Failed to create yamux server: %v", err)
			tunnelConn.Close()
			continue
		}

		// Listen for client connections in a goroutine
		go func() {
			// Make sure we properly close both the session and the listener
			defer func() {
				log.Printf("Tunnel session from %s is ending, closing session", remoteAddr)
				session.Close()
				
				// Force unbind the port
				portMutex.Lock()
				if clientListener != nil && !clientListenerClosed {
					log.Printf("Explicitly closing listener on %s to release port", *listenAddr)
					clientListener.Close()
					clientListenerClosed = true
					
					// Small delay to ensure OS has time to release the port
					time.Sleep(500 * time.Millisecond)
				}
				portMutex.Unlock()
				
				log.Printf("Port %s should now be released", *listenAddr)
			}()
			
			// Lock during port binding
			portMutex.Lock()
			
			// Listen for client connections
			var err error
			clientListener, err = lc.Listen(context.Background(), "tcp", *listenAddr)
			clientListenerClosed = false
			
			if err != nil {
				portMutex.Unlock()
				log.Printf("Failed to listen for clients on %s: %v", *listenAddr, err)
				return
			}
			
			portMutex.Unlock()
			log.Printf("Listening for clients on %s for tunnel from %s", *listenAddr, remoteAddr)

			// Create a channel to signal when we need to stop accepting connections
			stopAccepting := make(chan struct{})
			
			// Monitor for session closure to trigger port release
			go func() {
				// Wait for session to close
				<-session.CloseChan()
				close(stopAccepting)
			}()

			for {
				// Use Accept with timeout to allow checking if session is closed
				clientListener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
				
				// Accept client connection
				clientConn, err := clientListener.Accept()
				
				// Check if we should stop accepting
				select {
				case <-stopAccepting:
					if clientConn != nil {
						clientConn.Close()
					}
					return
				default:
					// Continue accepting connections
				}
				
				if err != nil {
					// Check if it's just a timeout
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					
					// Real error
					log.Printf("Failed to accept client connection: %v", err)
					return
				}

				// Apply TCP optimizations
				if tcpConn, ok := clientConn.(*net.TCPConn); ok {
					tcpConn.SetNoDelay(true)
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(60 * time.Second)
					tcpConn.SetReadBuffer(256 * 1024)
					tcpConn.SetWriteBuffer(256 * 1024)
				}

				log.Printf("Client connected from %s to tunnel %s", clientConn.RemoteAddr(), remoteAddr)

				// Open a new stream to the tunnel client
				stream, err := session.OpenStream()
				if err != nil {
					log.Printf("Failed to open stream: %v", err)
					clientConn.Close()
					
					// If session is closed or we can't open streams, exit the loop
					if session.IsClosed() {
						return
					}
					continue
				}

				// Handle connection in a goroutine
				go proxyClientConnection(clientConn, stream)
			}
		}()
	}
}

func proxyClientConnection(clientConn, stream net.Conn) {
	defer clientConn.Close()
	defer stream.Close()

	// Use waitgroup to properly handle bidirectional copy completion
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Copy data in both directions with buffered I/O
	go func() {
		defer wg.Done()
		bufferSize := 64 * 1024 // 64KB buffers
		buffer := make([]byte, bufferSize)
		n, err := io.CopyBuffer(stream, clientConn, buffer)
		if err != nil {
			log.Printf("Error copying client->stream: %v", err)
		}
		log.Printf("Copied %d bytes from client to stream", n)
	}()
	
	go func() {
		defer wg.Done()
		bufferSize := 64 * 1024 // 64KB buffers
		buffer := make([]byte, bufferSize)
		n, err := io.CopyBuffer(clientConn, stream, buffer)
		if err != nil {
			log.Printf("Error copying stream->client: %v", err)
		}
		log.Printf("Copied %d bytes from stream to client", n)
	}()
	
	// Wait for both copy operations to complete
	wg.Wait()
	log.Printf("Client connection closed")
}
