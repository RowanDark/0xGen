package atlas

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents logging severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// SimpleLogger provides a basic Logger implementation.
type SimpleLogger struct {
	mu     sync.Mutex
	out    io.Writer
	level  Level
	prefix string
}

// NewSimpleLogger creates a new simple logger.
func NewSimpleLogger(out io.Writer, level Level) *SimpleLogger {
	if out == nil {
		out = os.Stdout
	}
	return &SimpleLogger{
		out:   out,
		level: level,
	}
}

// WithPrefix returns a new logger with the given prefix.
func (l *SimpleLogger) WithPrefix(prefix string) *SimpleLogger {
	return &SimpleLogger{
		out:    l.out,
		level:  l.level,
		prefix: prefix,
	}
}

// Debug logs a debug message.
func (l *SimpleLogger) Debug(msg string, keyvals ...interface{}) {
	if l.level <= LevelDebug {
		l.log(LevelDebug, msg, keyvals...)
	}
}

// Info logs an info message.
func (l *SimpleLogger) Info(msg string, keyvals ...interface{}) {
	if l.level <= LevelInfo {
		l.log(LevelInfo, msg, keyvals...)
	}
}

// Warn logs a warning message.
func (l *SimpleLogger) Warn(msg string, keyvals ...interface{}) {
	if l.level <= LevelWarn {
		l.log(LevelWarn, msg, keyvals...)
	}
}

// Error logs an error message.
func (l *SimpleLogger) Error(msg string, keyvals ...interface{}) {
	if l.level <= LevelError {
		l.log(LevelError, msg, keyvals...)
	}
}

func (l *SimpleLogger) log(level Level, msg string, keyvals ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Build log line
	var sb strings.Builder
	sb.WriteString(time.Now().Format("2006-01-02T15:04:05.000Z07:00"))
	sb.WriteString(" ")
	sb.WriteString(level.String())
	sb.WriteString(" ")

	if l.prefix != "" {
		sb.WriteString("[")
		sb.WriteString(l.prefix)
		sb.WriteString("] ")
	}

	sb.WriteString(msg)

	// Append key-value pairs
	if len(keyvals) > 0 {
		for i := 0; i < len(keyvals); i += 2 {
			sb.WriteString(" ")
			if i+1 < len(keyvals) {
				sb.WriteString(fmt.Sprintf("%v=%v", keyvals[i], keyvals[i+1]))
			} else {
				sb.WriteString(fmt.Sprintf("%v=<missing>", keyvals[i]))
			}
		}
	}

	sb.WriteString("\n")
	fmt.Fprint(l.out, sb.String())
}

// NopLogger is a no-op logger that discards all messages.
type NopLogger struct{}

// NewNopLogger creates a new no-op logger.
func NewNopLogger() *NopLogger {
	return &NopLogger{}
}

// Debug does nothing.
func (l *NopLogger) Debug(msg string, keyvals ...interface{}) {}

// Info does nothing.
func (l *NopLogger) Info(msg string, keyvals ...interface{}) {}

// Warn does nothing.
func (l *NopLogger) Warn(msg string, keyvals ...interface{}) {}

// Error does nothing.
func (l *NopLogger) Error(msg string, keyvals ...interface{}) {}
