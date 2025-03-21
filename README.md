# HTTP Request Logger

A simple HTTP(S) server that logs all incoming requests.

## Features

- Logging of all HTTP/HTTPS requests
- Flexible protocol selection (HTTP or HTTPS)
- Captures:
  - Timestamp
  - HTTP method
  - Path
  - IP address
  - Headers
  - Request body
  - Query parameters
- Logging to both console and file
- Smart TLS certificate management:
  - Automatic self-signed certificates for localhost/IP
  - Let's Encrypt integration for real domains
- Development-friendly HTTPS setup by default

## Installation

You can install the Request Logger in two ways:

### Option 1: Direct Installation

Install directly using Go:

```bash
go install github.com/m10x/requestlogger@latest
```

After installation, you can run it from anywhere using:

```bash
requestlogger
```

### Option 2: Clone Repository

Clone and build from source:

```bash
git clone [repository-url]
cd RequestLogger
go mod download
```

Then run it using:

```bash
go run main.go
```

## Usage

### Basic Server

Start the server with default settings (HTTPS):

```bash
go run main.go
```

By default:
- Uses HTTPS protocol with self-signed certificate
- Runs on port 8443
- Listens on all interfaces (0.0.0.0)
- Uses automatic certificate management

### Command Line Parameters

The server supports the following command line parameters:

- `-protocol`: Protocol to use (default: "https", can be "http" or "https")
- `-ip`: IP address to listen on (default: "0.0.0.0", listens on all interfaces)
- `-port`: Port to run the server on (default: "8443")
- `-log`: Path to the log file (default: "logs/requests.log")
- `-cert`: Path to TLS certificate file for HTTPS (optional)
- `-key`: Path to TLS private key file for HTTPS (optional)
- `-domain`: Domain name for Let's Encrypt certificate (optional)

Examples:

```bash
# Run as HTTP server
go run main.go -protocol http -port 8080

# Run as HTTPS server on standard ports
go run main.go -port 443

# Run on a specific IP address (will include IP in certificate)
go run main.go -ip 192.168.1.100

# Run on localhost only
go run main.go -ip 127.0.0.1

# Specify a custom log file
go run main.go -log /var/log/requests.log

# Run with a real domain (will use Let's Encrypt)
go run main.go -domain example.com

# Run with existing certificates
go run main.go -cert /path/to/cert.pem -key /path/to/key.pem

# Combine multiple options
go run main.go -ip 192.168.1.100 -port 443 -domain example.com
```

### TLS/HTTPS Support

The server handles TLS in three ways:

1. **Automatic Self-Signed Certificates (Default for localhost/IP)**
   - Automatically generates self-signed certificates
   - Valid for localhost and specified IP addresses
   - Perfect for development and testing
   - No configuration needed
   - Valid for 1 year
   - Note: Browsers will show a security warning (normal for self-signed certificates)

2. **Let's Encrypt Integration (For real domains)**
   - Automatically obtains certificates from Let's Encrypt
   - Uses staging environment by default
   - Requires a valid domain name
   - Certificates are stored in the `certificates` directory
   - Handles automatic renewal

3. **Custom Certificates**
   - Use your own certificates by providing the paths:
   ```bash
   go run main.go -cert /path/to/cert.pem -key /path/to/key.pem
   ```

## Log Format

Each request is logged in the following JSON format:

```json
{
  "timestamp": "2024-03-21T10:00:00Z",
  "method": "GET",
  "path": "/example",
  "remote_addr": "127.0.0.1",
  "headers": {
    "User-Agent": ["Mozilla/5.0 ..."],
    "Accept": ["*/*"]
  },
  "body": "request body content",
  "query_params": {
    "param1": ["value1"],
    "param2": ["value2"]
  }
}
```