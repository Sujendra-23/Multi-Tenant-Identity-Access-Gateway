package observability

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type ctxKey string

const loggerKey ctxKey = "logger"

// NewLogger returns a JSON structured logger. Production runs at info; anything
// else runs at debug so local development shows the full verification chain.
func NewLogger(env string) *slog.Logger {
	level := slog.LevelDebug
	if env == "production" {
		level = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Defence in depth: even if a caller logs a secret by mistake, the
			// value never reaches stdout.
			if isSensitiveKey(a.Key) {
				return slog.String(a.Key, "[redacted]")
			}
			return a
		},
	})
	return slog.New(h)
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"password", "secret", "token", "authorization", "cookie", "private_key"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// WithLogger attaches a request-scoped logger to the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// LoggerFrom returns the request-scoped logger, falling back to the default.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
