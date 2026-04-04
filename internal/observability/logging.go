// Package observability provides metrics, tracing, and logging setup.
package observability

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// SetupLogging configures the global slog logger.
func SetupLogging(level, format string) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	var out io.Writer = os.Stdout

	switch strings.ToLower(format) {
	case "text":
		handler = slog.NewTextHandler(out, opts)
	default:
		handler = slog.NewJSONHandler(out, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
