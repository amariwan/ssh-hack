package util

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// SlogLogger implements Logger using slog
type SlogLogger struct {
	logger *slog.Logger
}

// NewLogger creates a new structured logger
// InitLogger initializes a structured logger that writes to stderr by default.
// If logFile is non-empty it will also write to the provided file path (appended).
func InitLogger(level string, logFile string) (Logger, error) {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	var writer io.Writer = os.Stderr
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = io.MultiWriter(os.Stderr, f)
	}

	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: slogLevel,
	})
	logger := slog.New(handler)

	return &SlogLogger{logger: logger}, nil
}

// NewLogger kept for backward compatibility and writes to stderr only.
func NewLogger(level string) Logger {
	lg, _ := InitLogger(level, "")
	return lg
}

func (l *SlogLogger) Debug(msg string, args ...interface{}) {
	l.logger.Debug(msg, args...)
}

func (l *SlogLogger) Info(msg string, args ...interface{}) {
	l.logger.Info(msg, args...)
}

func (l *SlogLogger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(msg, args...)
}

func (l *SlogLogger) Error(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
}

// Sanitizer redacts sensitive information from logs
type Sanitizer struct {
	patterns []*regexp.Regexp
}

// NewSanitizer creates a new sanitizer
func NewSanitizer() *Sanitizer {
	patterns := []*regexp.Regexp{
		// SSH private keys
		regexp.MustCompile(`(?i)(-----BEGIN.*PRIVATE KEY-----)[\s\S]+(-----END.*PRIVATE KEY-----)`),
		// Passwords in URLs
		regexp.MustCompile(`(?i)(password|passwd|pwd)[:=]\s*\S+`),
		// API tokens
		regexp.MustCompile(`(?i)(token|api[_-]?key|secret)[:=]\s*[a-zA-Z0-9_\-]+`),
		// SSH connection strings with passwords
		regexp.MustCompile(`ssh://[^:]+:[^@]+@`),
	}

	return &Sanitizer{patterns: patterns}
}

// Sanitize removes sensitive data from string
func (s *Sanitizer) Sanitize(input string) string {
	result := input
	for _, pattern := range s.patterns {
		result = pattern.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

// SanitizeMap sanitizes string values in a map
func (s *Sanitizer) SanitizeMap(input map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range input {
		switch val := v.(type) {
		case string:
			result[k] = s.Sanitize(val)
		case map[string]interface{}:
			result[k] = s.SanitizeMap(val)
		default:
			result[k] = v
		}
	}
	return result
}

// FormatError creates a sanitized error message
func FormatError(err error, context string) string {
	sanitizer := NewSanitizer()
	msg := fmt.Sprintf("%s: %v", context, err)
	return sanitizer.Sanitize(msg)
}
