package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const (
	version = "1.0.1"
	banner  = `
 ____                           _   _                            
|  _ \ ___  __ _ _   _  ___  ___| |_| |    ___   __ _  __ _  ___ _ __ 
| |_) / _ \/ _' | | | |/ _ \/ __| __| |   / _ \ / _' |/ _' |/ _ \ '__|
|  _ <  __/ (_| | |_| |  __/\__ \ |_| |__| (_) | (_| | (_| |  __/ |   
|_| \_\___|\__, |\__,_|\___||___/\__|_____\___/ \__, |\__, |\___|_|   
           |___/                                 |___/ |___/           
Version: %s
`
)

// printBanner prints the ASCII art banner with version
func printBanner() {
	fmt.Printf(banner, version)
	fmt.Println()
}

// RequestLog represents the structure for logging HTTP request information
type RequestLog struct {
	Timestamp   string              `json:"timestamp"`
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	RemoteAddr  string              `json:"remote_addr"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	QueryParams map[string][]string `json:"query_params"`
}

// Config holds the server configuration
type Config struct {
	IP       string
	Port     string
	Protocol string
	LogFile  string
	CertFile string
	KeyFile  string
	Domain   string
}

// setupLogging initializes the logging to both console and file
func setupLogging(logFile string) (*os.File, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("logs", 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Open log file
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Set up multi-writer to log to both console and file
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime)

	return file, nil
}

// logHandler wraps the request handling with logging functionality
func logHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		// Restore the body for further processing if needed
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Create request log entry
		reqLog := RequestLog{
			Timestamp:   time.Now().Format(time.RFC3339),
			Method:      r.Method,
			Path:        r.URL.Path,
			RemoteAddr:  r.RemoteAddr,
			Headers:     r.Header,
			Body:        string(bodyBytes),
			QueryParams: r.URL.Query(),
		}

		// Convert to JSON for logging
		logJSON, err := json.MarshalIndent(reqLog, "", "  ")
		if err != nil {
			log.Printf("Error marshaling request log: %v", err)
		} else {
			log.Printf("Incoming Request:\n%s\n", string(logJSON))
		}

		// Call the next handler
		next(w, r)
	}
}

// defaultHandler handles all incoming requests
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Request logged successfully")
}

// generateSelfSignedCert creates a self-signed certificate for development
func generateSelfSignedCert(hosts []string) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"RequestLogger Development"},
			CommonName:   hosts[0],
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add all hosts as SANs
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}

	return cert, nil
}

func main() {
	// Print banner
	printBanner()

	// Parse command line flags
	config := Config{}
	flag.StringVar(&config.IP, "ip", "0.0.0.0", "IP address to listen on (0.0.0.0 for all interfaces)")
	flag.StringVar(&config.Port, "port", "8443", "Port to run the server on")
	flag.StringVar(&config.Protocol, "protocol", "https", "Protocol to use (http or https)")
	flag.StringVar(&config.LogFile, "log", "logs/requests.log", "Path to the log file")
	flag.StringVar(&config.CertFile, "cert", "", "Path to TLS certificate file")
	flag.StringVar(&config.KeyFile, "key", "", "Path to TLS private key file")
	flag.StringVar(&config.Domain, "domain", "localhost", "Domain name for the certificate")
	flag.Parse()

	// Validate protocol
	config.Protocol = strings.ToLower(config.Protocol)
	if config.Protocol != "http" && config.Protocol != "https" {
		log.Fatalf("Invalid protocol %q. Must be 'http' or 'https'", config.Protocol)
	}

	// Setup logging
	logFile, err := setupLogging(config.LogFile)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logFile.Close()

	// Setup routes
	http.HandleFunc("/", logHandler(defaultHandler))

	// Configure server
	addr := fmt.Sprintf("%s:%s", config.IP, config.Port)

	if config.Protocol == "http" {
		log.Printf("Starting HTTP server on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
		return
	}

	// HTTPS handling
	useTLS := config.CertFile != "" && config.KeyFile != ""

	if useTLS {
		// Use provided certificates
		log.Printf("Starting HTTPS server on %s", addr)
		if err := http.ListenAndServeTLS(addr, config.CertFile, config.KeyFile, nil); err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	} else {
		// Use certmagic for automatic certificate management
		log.Printf("Starting HTTPS server with certificate management on %s", addr)

		// Create list of domains
		var domains []string
		if config.Domain != "localhost" && config.Domain != "" {
			domains = append(domains, config.Domain)
		}

		var server *http.Server
		if len(domains) > 0 {
			// Use Let's Encrypt for real domains
			certmagic.Default.Storage = &certmagic.FileStorage{Path: "certificates"}
			certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

			tlsConfig, err := certmagic.TLS(domains)
			if err != nil {
				log.Fatalf("Failed to create certificate manager: %v", err)
			}

			server = &http.Server{
				Addr:      addr,
				Handler:   nil,
				TLSConfig: tlsConfig,
			}
		} else {
			// Use self-signed certificate for localhost/IP
			hosts := []string{"localhost"}
			if config.IP != "0.0.0.0" {
				hosts = append(hosts, config.IP)
			}

			cert, err := generateSelfSignedCert(hosts)
			if err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}

			server = &http.Server{
				Addr:    addr,
				Handler: nil,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{*cert},
				},
			}
			log.Printf("Using self-signed certificate for %v", hosts)
		}

		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	}
}
