// Package connect is the module of ndagent-connect, the companion ndagent
// starts for each remote access session of the "direct-peer + encrypted
// relay" transport. It is a module of its own so that the tunnel library, the
// Go release it needs and everything it depends on stay out of the agent's
// module: the two share no code, only what internal/ipc describes.
//
// The command is cmd/ndagent-connect. Build it with the tags in
// build-tags.txt, as the Makefile at the top of the repository does.
package connect
