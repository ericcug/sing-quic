package queqiao

import (
	"context"
	"log/slog"

	"github.com/sagernet/sing/common/logger"
)

// newSlogLogger adapts a sing logger to the std slog.Logger the queqiao core
// writes to, so every line it emits follows the host's log level and format.
func newSlogLogger(target logger.Logger) *slog.Logger {
	return slog.New(&slogHandler{logger: target})
}

type slogHandler struct {
	logger logger.Logger
	attrs  []slog.Attr
}

func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	message := record.Message
	if len(h.attrs) > 0 || record.NumAttrs() > 0 {
		message += " "
		first := true
		appendAttr := func(attr slog.Attr) {
			if !first {
				message += " "
			}
			first = false
			message += attr.String()
		}
		for _, attr := range h.attrs {
			appendAttr(attr)
		}
		record.Attrs(func(attr slog.Attr) bool {
			appendAttr(attr)
			return true
		})
	}
	switch {
	case record.Level >= slog.LevelError:
		h.logger.Error(message)
	case record.Level >= slog.LevelWarn:
		h.logger.Warn(message)
	case record.Level >= slog.LevelInfo:
		h.logger.Info(message)
	case record.Level >= slog.LevelDebug:
		h.logger.Debug(message)
	default:
		h.logger.Trace(message)
	}
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &slogHandler{logger: h.logger, attrs: merged}
}

func (h *slogHandler) WithGroup(string) slog.Handler {
	return h
}
