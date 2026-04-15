// Package logging provides centralized logging configuration for NDAgent.
package logging

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Mode represents the logging mode.
type Mode string

const (
	// ModeForeground outputs logs to stdout with timestamps.
	ModeForeground Mode = "foreground"
	// ModeService outputs logs to syslog (for OPNsense).
	ModeService Mode = "service"
)

// ProgramName is the program identifier for syslog.
const ProgramName = "ndagent"

// SyslogAddress is the syslog socket path for OPNsense.
const SyslogAddress = "/var/run/log"

var (
	// global logger instance
	globalLogger *zap.Logger
	// sugar logger for convenience
	globalSugar *zap.SugaredLogger
	// current mode
	currentMode Mode
)

// Setup initializes the logging system.
func Setup(mode Mode, level string) error {
	currentMode = mode

	// Parse log level
	zapLevel, err := parseLevel(level)
	if err != nil {
		return err
	}

	var logger *zap.Logger

	switch mode {
	case ModeForeground:
		logger, err = setupForegroundLogger(zapLevel)
	case ModeService:
		logger, err = setupServiceLogger(zapLevel)
	default:
		return fmt.Errorf("invalid logging mode: %s (must be 'foreground' or 'service')", mode)
	}

	if err != nil {
		return fmt.Errorf("failed to setup logger: %w", err)
	}

	globalLogger = logger
	globalSugar = logger.Sugar()

	globalSugar.Infow("Logging initialized",
		"mode", string(mode),
		"level", level,
		"program", ProgramName,
	)

	return nil
}

// parseLevel converts a string level to zapcore.Level.
func parseLevel(level string) (zapcore.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return zapcore.DebugLevel, nil
	case "INFO":
		return zapcore.InfoLevel, nil
	case "WARNING", "WARN":
		return zapcore.WarnLevel, nil
	case "ERROR":
		return zapcore.ErrorLevel, nil
	case "CRITICAL":
		return zapcore.ErrorLevel, nil // Map CRITICAL to ERROR in zap
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %s", level)
	}
}

// setupForegroundLogger creates a console logger with timestamps.
func setupForegroundLogger(level zapcore.Level) (*zap.Logger, error) {
	// Custom encoder config for foreground mode
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}

	// Create console encoder
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// Create core
	core := zapcore.NewCore(
		consoleEncoder,
		zapcore.AddSync(os.Stdout),
		level,
	)

	return zap.New(core), nil
}

// setupServiceLogger creates a syslog logger for service mode.
func setupServiceLogger(level zapcore.Level) (*zap.Logger, error) {
	// Try to connect to syslog
	writer, err := syslog.Dial("unixgram", SyslogAddress, syslog.LOG_INFO|syslog.LOG_DAEMON, ProgramName)
	if err != nil {
		// Fallback to console if syslog is not available
		return setupForegroundLogger(level)
	}

	// Custom encoder config for syslog (no timestamp - syslog adds it)
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}

	// Create console encoder (plain text for syslog)
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	// Create syslog writer wrapper
	core := zapcore.NewCore(
		encoder,
		&syslogWriteSyncer{writer: writer},
		level,
	)

	return zap.New(core), nil
}

// syslogWriteSyncer wraps syslog.Writer to implement zapcore.WriteSyncer.
type syslogWriteSyncer struct {
	writer *syslog.Writer
}

func (s *syslogWriteSyncer) Write(p []byte) (int, error) {
	// Remove trailing newline if present (syslog adds its own)
	msg := strings.TrimSuffix(string(p), "\n")
	return len(p), s.writer.Info(msg)
}

func (s *syslogWriteSyncer) Sync() error {
	return nil
}

// Logger returns the global logger.
func Logger() *zap.Logger {
	if globalLogger == nil {
		// Return a no-op logger if Setup hasn't been called
		return zap.NewNop()
	}
	return globalLogger
}

// Sugar returns the global sugared logger for convenience methods.
func Sugar() *zap.SugaredLogger {
	if globalSugar == nil {
		return zap.NewNop().Sugar()
	}
	return globalSugar
}

// Named returns a named logger.
func Named(name string) *zap.SugaredLogger {
	return Sugar().Named(name)
}

// SetLevel changes the log level dynamically.
func SetLevel(level string) error {
	_, err := parseLevel(level)
	if err != nil {
		return err
	}

	// Recreate logger with new level
	return Setup(currentMode, level)
}

// IsServiceMode returns whether logging is configured for service mode.
func IsServiceMode() bool {
	return currentMode == ModeService
}

// Sync flushes any buffered log entries.
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}
