package html

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/amariwan/ssh-hack/internal/util"
)

// Server serves HTML reports via HTTP
type Server struct {
	reportPath string
	port       int
	logger     util.Logger
}

// NewServer creates a read-only HTTP server for reports
func NewServer(reportPath string, port int, logger util.Logger) *Server {
	return &Server{
		reportPath: reportPath,
		port:       port,
		logger:     logger,
	}
}

// Serve starts the HTTP server
func (s *Server) Serve() error {
	// Ensure report exists
	if _, err := os.Stat(s.reportPath); os.IsNotExist(err) {
		return fmt.Errorf("report file not found: %s", s.reportPath)
	}

	// Get absolute path
	absPath, err := filepath.Abs(s.reportPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Single-file server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.logger.Debug("Serving report", "path", r.URL.Path, "remote", r.RemoteAddr)
		http.ServeFile(w, r, absPath)
	})

	addr := fmt.Sprintf("localhost:%d", s.port)
	s.logger.Info("Starting HTTP server", "url", fmt.Sprintf("http://%s", addr))
	fmt.Printf("\n📊 Dashboard available at: http://%s\n", addr)
	fmt.Println("Press Ctrl+C to stop")

	return http.ListenAndServe(addr, nil)
}
