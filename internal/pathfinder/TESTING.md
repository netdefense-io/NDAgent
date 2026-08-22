# Testing internal/pathfinder

## HandleStream tests and the context-cancellation false-pass trap

`HTTPProxy.HandleStream` (`httpproxy.go`) ties each request's `context.Context` to
the stream's lifetime: a goroutine calls `cancel()` the instant `stream.CloseChan()`
fires. Closing the stream is not neutral teardown — it actively aborts any request
still in flight via `forwardRequest`.

This matters for any `HandleStream`-level test asserting that a request was
**never** forwarded to the backend (e.g. a read-only bypass check). A test that
closes the stream immediately after capturing the expected response can falsely
pass even when the bypass bug is real: closing the stream cancels the context,
which aborts the in-flight (buggy) `forwardRequest` call before it reaches the
backend. The test then observes "backend never hit" and reports success — but
that's the cancellation racing the bug, not proof the bug doesn't exist.

**Fix:** hold the stream open through a bounded confirmation window before closing
it, and only close after that window elapses with no forwarded request observed.
That gives a real bypass enough time to actually complete and get caught.

See `assertSentinelNeverHitWithin` in `httpproxy_test.go` for the helper, and
`TestHandleStream_ReadOnlyBlocksServiceRestart_DoesNotForward` /
`TestHandleStream_ReadOnlyBlocksFlushStates_DoesNotForward` for it in use: both
hold the stream open for a window before closing, and assert on the sentinel
backend's hit-count rather than just the HTTP status, so a forward that raced the
close can't hide behind an otherwise-correct 405.
