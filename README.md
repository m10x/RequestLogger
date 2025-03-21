# HTTP Request Logger

A simple HTTP server that logs all incoming requests.

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
- Automatic TLS certificate management using certmagic
- Development-friendly HTTPS setup by default

## Installation

You can install the Request Logger in two ways:

### Option 1: Direct Installation

Install directly using Go:

```bash
go install github.com/yourusername/requestlogger@latest
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
- Uses HTTPS protocol
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
- `-domain`: Additional domain name for the certificate (optional)

Examples:

```bash
# Run as HTTP server
go run main.go -protocol http -port 8080

# Run as HTTPS server on standard ports
go run main.go -port 443

# Run on a specific IP address
go run main.go -ip 192.168.1.100

# Run on localhost only
go run main.go -ip 127.0.0.1

# Specify a custom log file
go run main.go -log /var/log/requests.log

# Run with additional domain name
go run main.go -domain example.com

# Run with existing certificates
go run main.go -cert /path/to/cert.pem -key /path/to/key.pem

# Combine multiple options
go run main.go -ip 192.168.1.100 -port 443 -domain example.com
```

### TLS/HTTPS Support

The server handles TLS in two ways:

1. **Automatic Certificate Management (Default)**
   - Uses certmagic to automatically manage certificates
   - Always uses Let's Encrypt's staging environment for development-friendly setup
   - Certificate is valid for:
     - localhost
     - Server IP (if specified)
     - Additional domain (if specified)
   - Certificates are stored in the `certificates` directory
   - Handles automatic renewal

2. **Custom Certificates**
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

## Production Use

When using this server in production:

1. Make sure your domain points to the server's IP address
2. Consider using your own certificates instead of the staging environment
3. Ensure port 80 and 443 are accessible (required for Let's Encrypt verification)
4. Consider binding to specific IP addresses for better security
5. Always use HTTPS in production unless there's a specific requirement for HTTP

**Note**: By default, the server uses Let's Encrypt's staging environment, which means browsers will show a security warning. This is intentional for development purposes. For production use, you should provide your own certificates.