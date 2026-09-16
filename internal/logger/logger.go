package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

// LogLevel defines a logging level.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// Logger writes application log messages.
type Logger struct {
	mu      sync.Mutex
	verbose bool
	logger  *log.Logger
	level   LogLevel
	file    *os.File
}

// NewLogger creates a logger.
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
		logger:  log.New(os.Stdout, "", log.LstdFlags),
		level:   LevelInfo,
	}
}

// SetLogFile adds a file destination for log messages.
func (l *Logger) SetLogFile(filePath string) error {
	if filePath == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf(i18n.T("failed to create the log directory: %w"), err)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf(i18n.T("failed to open the log file: %w"), err)
	}

	if l.file != nil {
		l.file.Close()
	}

	l.file = file

	writer := io.MultiWriter(os.Stdout, file)
	l.logger.SetOutput(writer)

	return nil
}

// SetLevel sets the minimum logging level.
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	var prefix string

	switch level {
	case LevelDebug:
		prefix = "[DEBUG] "
	case LevelInfo:
		prefix = "[INFO] "
	case LevelWarn:
		prefix = "[WARN] "
	case LevelError:
		prefix = "[ERROR] "
	case LevelFatal:
		prefix = "[FATAL] "
	}

	msg := fmt.Sprintf(format, args...)
	l.logger.Println(prefix + msg)
}

func (l *Logger) Debug(msg string) {
	if l.verbose {
		l.log(LevelDebug, "%s", msg)
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.verbose {
		l.log(LevelDebug, format, args...)
	}
}

func (l *Logger) Info(msg string) {
	l.log(LevelInfo, "%s", msg)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

func (l *Logger) Warn(msg string) {
	l.log(LevelWarn, "%s", msg)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

func (l *Logger) Error(msg string) {
	l.log(LevelError, "%s", msg)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

func (l *Logger) Fatal(msg string) {
	l.log(LevelFatal, "%s", msg)
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, format, args...)
	os.Exit(1)
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
