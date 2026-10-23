package network

import (
	"os"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// logSink is the logger of every test in this package, installed before any of
// them runs. Replacing the global logger later would race with the goroutines
// of a connection, which outlive it; a test that reads what was logged points
// the sink at an observer instead (captureLogs).
var logSink = &switchCore{inner: zapcore.NewNopCore()}

func TestMain(m *testing.M) {
	logging.SetForTest(zap.New(logSink))
	os.Exit(m.Run())
}

// captureLogs records everything logged until the test ends.
func captureLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	logSink.set(core)
	t.Cleanup(func() { logSink.set(zapcore.NewNopCore()) })
	return logs
}

// switchCore writes to whichever core it currently points at.
type switchCore struct {
	mu    sync.RWMutex
	inner zapcore.Core
}

func (s *switchCore) current() zapcore.Core {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *switchCore) set(c zapcore.Core) {
	s.mu.Lock()
	s.inner = c
	s.mu.Unlock()
}

func (s *switchCore) Enabled(l zapcore.Level) bool { return s.current().Enabled(l) }
func (s *switchCore) With(fields []zapcore.Field) zapcore.Core {
	return fieldsCore{sink: s, fields: fields}
}
func (s *switchCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if s.Enabled(e.Level) {
		return ce.AddCore(e, s)
	}
	return ce
}
func (s *switchCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	return s.current().Write(e, fields)
}
func (s *switchCore) Sync() error { return s.current().Sync() }

// fieldsCore is the sink with fields a logger added (zap's With).
type fieldsCore struct {
	sink   *switchCore
	fields []zapcore.Field
}

func (f fieldsCore) Enabled(l zapcore.Level) bool { return f.sink.Enabled(l) }
func (f fieldsCore) With(fields []zapcore.Field) zapcore.Core {
	return fieldsCore{sink: f.sink, fields: append(append([]zapcore.Field(nil), f.fields...), fields...)}
}
func (f fieldsCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if f.Enabled(e.Level) {
		return ce.AddCore(e, f)
	}
	return ce
}
func (f fieldsCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	return f.sink.current().Write(e, append(append([]zapcore.Field(nil), f.fields...), fields...))
}
func (f fieldsCore) Sync() error { return f.sink.Sync() }
