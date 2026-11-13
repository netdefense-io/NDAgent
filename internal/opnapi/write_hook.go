package opnapi

import "context"

type writeHookKey struct{}

// WithWriteHook returns a context whose requests that are not idempotent reads
// call hook with their method and path before they are sent, whether or not
// they then succeed. The client is shared across tasks, so a task scopes its
// hook with its own context.
func WithWriteHook(ctx context.Context, hook func(method, path string)) context.Context {
	return context.WithValue(ctx, writeHookKey{}, hook)
}

func noteWrite(ctx context.Context, method, path string) {
	if hook, ok := ctx.Value(writeHookKey{}).(func(method, path string)); ok && hook != nil {
		hook(method, path)
	}
}
