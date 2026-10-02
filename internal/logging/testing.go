package logging

import "go.uber.org/zap"

// SetForTest replaces the global logger for a test that reads what was logged,
// and returns a function that restores the previous one. Production code
// never calls it. Loggers taken from Named before the call keep the old one.
func SetForTest(logger *zap.Logger) (restore func()) {
	prevLogger, prevSugar := globalLogger, globalSugar
	globalLogger, globalSugar = logger, logger.Sugar()
	return func() { globalLogger, globalSugar = prevLogger, prevSugar }
}
