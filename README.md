# Finger Trap

Finger Trap is a reverse SSH server that runs a local SSH server and exposes it to a remote host through a reverse tunnel. There are many other projects that already do this, this is just my own implementation built to solve a specific scenario I encountered.
 
This can be used as a way to deploy a simple standalone SSH server for tunneling traffic through a firewalled system. This is intended to be a solution for niche circumstances where the use of OpenSSH and traditional SSH tunneling approaches is not possible or desirable.

## Components
There are two components that are described below:

### Tunnel Server
This component runs on a publicly accessible machine on the Internet and:
- Listens for tunnel client connections on a public port (default: 9000)
- Accepts SSH connections from the tunneling client on a separate port (default: 2222)
- Forwards connections from the public port to the tunneling client

### Tunnel Client
This component runs on the firewalled machine that you want to tunnel traffic through, and:
- Starts an SSH server with port forwarding and SFTP/SCP support on a local port (default: 127.0.0.1:2222)
- Connects outbound to the tunnel server via its public port (default: 9000)
- Receives forwarded connections from the tunnel server and routes them to the local SSH server

## Considerations
 - The SSH server intentionally doesn't include a PTY or any ability to run commands or code
 - The SSH server accepts any username (authentication is key-based only, with keys hardcoded into the tunnel client binary)
 - If the tunnel client disconnects, it will automatically attempt to reconnect (i.e. there is some level of resiliency to connection drops)
 - The connection between the tunnel client and tunnel server uses TLS and checks for a hardcoded certificate fingerprint (i.e. environments with TLS inspection might break this)

## Usage

### 1. Configure SSH Keys

Add your public SSH keys to the `authorizedKeysData` array in `client.go`:

```go
var authorizedKeysData = []string{
    "ssh-ed25519 AAAA.... example",
}
```

### 2. Generate a new SSH host key

Generate and add a hardcoded SSH host key in `client.go`:
```bash
ssh-keygen -t ed25519 -f host_key -N ""
```

Replace the `hostKeyData` constant with the contents of the generated key.

```go
const hostKeyData = `-----BEGIN OPENSSH PRIVATE KEY-----
AAAA....
-----END OPENSSH PRIVATE KEY-----`
```

### 3. Generate a self-signed TLS certificate and update fingerprint

Generate a self-signed certificate and private key for the server:
```bash
cd server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=fingertrap"
openssl x509 -in server.crt -fingerprint -sha256 -noout
```

The `server.crt` and `server.key` files should be placed alongside the `server` binary when you run it later.

Next, replace the `serverCertFingerprint` constant in `client.go` with the output from the previous command:
```go
const serverCertFingerprint = "SHA256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
```

### 4. Configure server IP address and port
The client needs to know the IP address and port of your publicly facing server. Replace the `remoteAddr` constant in `client.go` with your IP address and port:

```go
const remoteAddr = "203.0.113.123:9000"
```

### 5. Build the tunnel server and tunnel client

Install Go and build the binaries for both the tunnel server and tunnel client:

```bash
cd server
go mod tidy
go build
```

```bash
cd client
go mod tidy
go build
```

### 6. Start the tunnel server

On your publicly accessible server:

```bash
./server
```

### 7. Start the tunnel client

On your local machine:
```bash
./client
```

### 8. Connect to the SSH Server

On your publicly accessible server, you can now connect to the remote SSH server on your firewalled system via the local loopback interface:

```bash
ssh user@127.0.0.1 -p 2222
```

You can use normal OpenSSH client port forwarding functionality to tunnel traffic through the remote system:

```bash
ssh user@127.0.0.1 -p 2222 -D 8080
curl --proxy socks://127.0.0.1:8080 https://www.example.com
```

You can copy files to and from the remote system with SCP:

```bash
scp -P 2222 something user@127.0.0.1:/tmp/something
```