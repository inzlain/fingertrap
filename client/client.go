package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/hashicorp/yamux"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 128*1024)
	},
}

// Hardcoded address/port of the remote tunnel server
const remoteAddr = "203.0.113.123:9000"
// Hardcoded address/port of the local interface to run the SSH server on
const localAddr = "127.0.0.1:2222"

// Hardcoded TLS fingerprint to verify the server against
// This should be the SHA-256 fingerprint of the server's certificate
const serverCertFingerprint = "SHA256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

// Hardcoded list of authorized SSH public keys
var authorizedKeysData = []string{
	// Add your SSH public keys here (in OpenSSH format)
	"ssh-rsa AAAA...CHANGEME example",
}

// Hardcoded SSH host key (in PEM format)
// This should be an RSA, ECDSA, or ED25519 private key in PEM format
// Generate with: ssh-keygen -t ed25519 -f host_key -N ""
const hostKeyData = `-----BEGIN OPENSSH PRIVATE KEY----- 
AAAA...CHANGEME
-----END OPENSSH PRIVATE KEY-----`

// Helper function to calculate certificate fingerprint
func getCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	// Convert to hex string with colons (similar to OpenSSL format)
	hexStr := hex.EncodeToString(hash[:])
	// Insert colons every 2 characters
	var result strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(hexStr[i : i+2])
	}
	return "SHA256:" + result.String()
}

// Certificate verification function for TLS connection
func verifyServerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificate presented by server")
	}
	
	// Parse the certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %v", err)
	}
	
	// Calculate its fingerprint
	fingerprint := getCertFingerprint(cert)
	
	// Check against our hardcoded fingerprint
	if strings.ToLower(fingerprint) != strings.ToLower(serverCertFingerprint) {
		return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", 
			serverCertFingerprint, fingerprint)
	}
	
	log.Printf("Server certificate fingerprint verified: %s", fingerprint)
	return nil
}

// SftpHandler handler for SFTP subsystem
func SftpHandler(sess ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		log.Println("sftp client exited session.")
	} else if err != nil {
		log.Println("sftp server completed with error:", err)
	}
}

// loadHostKey parses the hardcoded host key
func loadHostKey() (ssh.Signer, error) {
	// Parse the private key
	signer, err := gossh.ParsePrivateKey([]byte(hostKeyData))
	if err != nil {
		return nil, err
	}
	
	// Log the fingerprint
	fingerprint := gossh.FingerprintSHA256(signer.PublicKey())
	log.Printf("Loaded host key with fingerprint: %s", fingerprint)
	
	return signer, nil
}

// loadAuthorizedKeys parses the hardcoded authorized keys
func loadAuthorizedKeys() (map[string]bool, error) {
	authorizedKeys := make(map[string]bool)
	
	if len(authorizedKeysData) == 0 {
		log.Printf("WARNING: No authorized keys defined in source code!")
		log.Printf("No SSH connections will be accepted.")
		return authorizedKeys, nil
	}
	
	// Parse each key from the hardcoded list
	for i, keyData := range authorizedKeysData {
		pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(keyData))
		if err != nil {
			log.Printf("Error parsing authorized key #%d: %v", i+1, err)
			continue
		}
		
		// Add the key to our map (using fingerprint as key)
		fingerprint := gossh.FingerprintSHA256(pubKey)
		authorizedKeys[fingerprint] = true
		log.Printf("Loaded authorized key: %s", fingerprint)
	}
	
	return authorizedKeys, nil
}

// runForwardingClient runs the tunnel client and handles reconnection
func runForwardingClient(remoteAddr, localAddr string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	log.Printf("Starting forwarding client: connecting to %s, forwarding to %s", remoteAddr, localAddr)
	
	for {
		// Connect to the remote server
		log.Printf("Attempting to connect to remote server at %s...", remoteAddr)
		
		// Setup TLS configuration with certificate verification
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // We do our own verification below via VerifyPeerCertificate
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: verifyServerCert,
		}
		
		conn, err := tls.Dial("tcp", remoteAddr, tlsConfig)
		if err != nil {
			log.Printf("Forwarding client: Failed to connect with TLS to %s: %v", remoteAddr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("Forwarding client: Established secure TLS connection to %s", remoteAddr)
		
		// Log server certificate details
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			fingerprint := getCertFingerprint(cert)
			log.Printf("Server certificate: Subject=%s, Issuer=%s, Fingerprint=%s", 
				cert.Subject.CommonName, cert.Issuer.CommonName, fingerprint)
		}
		
		log.Printf("Forwarding client: Successfully connected to %s", remoteAddr)
		
		// Setup yamux client with optimizations
		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		config.AcceptBacklog = 512
		config.MaxStreamWindowSize = 1024 * 1024
		config.StreamOpenTimeout = 30 * time.Second
		config.ConnectionWriteTimeout = 10 * time.Second
		config.KeepAliveInterval = 30 * time.Second
		config.EnableKeepAlive = true
		session, err := yamux.Client(conn, config)
		if err != nil {
			log.Printf("Forwarding client: Failed to create yamux client: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		
		log.Printf("Forwarding client: Established yamux session with server")
		
		// Accept streams from the server and handle them
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("Forwarding client: Error accepting stream: %v", err)
				break
			}
			
			log.Printf("Forwarding client: Accepted new stream from server")
			
			// Handle the stream in a goroutine
			go handleStream(stream, localAddr)
		}
		
		// If we get here, the session has ended
		session.Close()
		conn.Close()
		log.Printf("Forwarding client: Connection to server lost. Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func handleStream(stream net.Conn, localAddr string) {
	defer stream.Close()
	
	// Connect to local service
	log.Printf("Forwarding client: Connecting to local service at %s", localAddr)
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("Forwarding client: Failed to connect to local service at %s: %v", localAddr, err)
		return
	}
	defer localConn.Close()
	
	// Apply TCP optimizations
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
		tcpConn.SetReadBuffer(512 * 1024)
		tcpConn.SetWriteBuffer(512 * 1024)
	}
	
	log.Printf("Forwarding client: Connected to local service, starting bidirectional traffic flow")
	
	// Create a WaitGroup for the copy operations
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Copy from stream to local connection
	go func() {
		defer wg.Done()
		// Get buffer from pool - downstream direction (server → client)
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)
		
		n, err := io.CopyBuffer(localConn, stream, buffer)
		
		if err != nil {
			log.Printf("Forwarding client: Error copying stream->local: %v", err)
		}
		
		log.Printf("Forwarding client: Copied %d bytes from stream to local", n)
		
		// Ensure the local connection is closed after copy is done
		localConn.Close()
	}()
	
	// Copy from local connection to stream
	go func() {
		defer wg.Done()
		// Get buffer from pool - upstream direction (client → server)
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)
		
		n, err := io.CopyBuffer(stream, localConn, buffer)
		
		if err != nil {
			log.Printf("Forwarding client: Error copying local->stream: %v", err)
		}
		
		log.Printf("Forwarding client: Copied %d bytes from local to stream", n)
		
		// Ensure the stream is closed after copy is done
		stream.Close()
	}()
	
	// Wait for both copy operations to complete
	wg.Wait()
	log.Printf("Forwarding client: Stream handling completed")
}

func runSSHServer(addr string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	log.Println("Starting SSH server on", addr)
	
	// Load authorized keys from hardcoded list
	authorizedKeys, err := loadAuthorizedKeys()
	if err != nil {
		log.Fatalf("Failed to load authorized keys: %v", err)
	}
	
	if len(authorizedKeys) == 0 {
		log.Printf("WARNING: No valid authorized keys found")
		log.Printf("No SSH connections will be accepted")
	} else {
		log.Printf("Loaded %d authorized keys", len(authorizedKeys))
	}
	
	// Load the hardcoded host key
	hostKey, err := loadHostKey()
	if err != nil {
		log.Fatalf("Failed to load host key: %v", err)
	}

	server := ssh.Server{
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			log.Println("Accepted forward", dhost, dport)
			return true
		}),
		PublicKeyHandler: ssh.PublicKeyHandler(func(ctx ssh.Context, key ssh.PublicKey) bool {
			// Check if the key is in our authorized keys
			fingerprint := gossh.FingerprintSHA256(key)
			isAuthorized := authorizedKeys[fingerprint]
			
			if isAuthorized {
				log.Printf("Accepted key %s from %s", fingerprint, ctx.RemoteAddr())
			} else {
				log.Printf("Rejected key %s from %s (not in authorized keys)", fingerprint, ctx.RemoteAddr())
			}
			
			return isAuthorized
		}),
		HostSigners: []ssh.Signer{hostKey}, // Use the hardcoded host key
		Addr: addr,
		Handler: ssh.Handler(func(s ssh.Session) {
			io.WriteString(s, "Connected...\n")
			select {}
		}),
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip":        ssh.DirectTCPIPHandler,
			"session":             ssh.DefaultSessionHandler,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("SSH server error: %v", err)
	}
}

func main() {
	// Create a wait group to keep the program running
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Start the SSH server in a goroutine
	go runSSHServer(localAddr, &wg)
	
	// Give the SSH server plenty of time to start up and start accepting connections
	time.Sleep(3 * time.Second)
	
	// Start the forwarding client in another goroutine
	go runForwardingClient(remoteAddr, localAddr, &wg)
	
	// Wait for both goroutines to complete (they won't under normal circumstances -> run indefinitely)
	wg.Wait()
}