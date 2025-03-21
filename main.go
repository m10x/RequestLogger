package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

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

func main() {
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
		log.Printf("Starting HTTPS server with automatic certificate management on %s", addr)

		// Configure certmagic
		certmagic.Default.Storage = &certmagic.FileStorage{Path: "certificates"}

		// Always use staging CA unless explicitly set to production
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

		// Create list of domains to be included in the certificate
		domains := []string{"localhost"}

		// Add IP if it's not 0.0.0.0
		if config.IP != "0.0.0.0" {
			domains = append(domains, config.IP)
		}

		// Add custom domain if specified and different from localhost
		if config.Domain != "localhost" {
			domains = append(domains, config.Domain)
		}

		// Create certificate manager
		tlsConfig, err := certmagic.TLS(domains)
		if err != nil {
			log.Fatalf("Failed to create certificate manager: %v", err)
		}

		server := &http.Server{
			Addr:      addr,
			Handler:   nil, // Use default handler
			TLSConfig: tlsConfig,
		}
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	}
}
