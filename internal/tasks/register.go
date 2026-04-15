package tasks

import (
	"github.com/netdefense-io/ndagent/internal/network"
)

// RegisterHandlers registers all task handlers with the WebSocket client's dispatcher.
func RegisterHandlers(ws *network.WebSocketClient) {
	dispatcher := ws.GetDispatcher()

	// Register system handlers
	dispatcher.RegisterHandler(network.TaskTypePing, HandlePing)
	dispatcher.RegisterHandler(network.TaskTypeShutdown, HandleShutdown)
	dispatcher.RegisterHandler(network.TaskTypeReboot, HandleReboot)
	dispatcher.RegisterHandler(network.TaskTypeRestart, HandleRestart)

	// Register config handlers (API-based)
	dispatcher.RegisterHandler(network.TaskTypePull, HandlePullAPI)
	dispatcher.RegisterHandler(network.TaskTypeSync, HandleSyncAPI)

	// Register backup handler
	dispatcher.RegisterHandler(network.TaskTypeBackup, HandleBackup)

	// Register remote access handler
	dispatcher.RegisterHandler(network.TaskTypeConnect, HandleConnect)
}
