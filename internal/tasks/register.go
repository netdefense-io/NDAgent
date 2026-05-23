package tasks

import (
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/taskstore"
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

	// Register plugin self-install handler
	dispatcher.RegisterHandler(network.TaskTypePluginInstall, HandlePluginInstall)
}

// LifecycleFor returns the taskstore Lifecycle category for a given task
// type. The dispatcher consults this at Begin time to record how the
// boot-time drain should treat any row left IN_PROGRESS — see the
// taskstore.Lifecycle docs for the per-category rules.
//
// Unknown task types default to LifecycleSynchronous: a crashed-mid-task
// FAILED is a more useful signal than treating the agent's return as
// success for something we don't recognize.
func LifecycleFor(taskType string) taskstore.Lifecycle {
	switch taskType {
	case network.TaskTypeRestart, network.TaskTypeReboot, network.TaskTypeShutdown:
		return taskstore.LifecycleRestartCompletes
	case network.TaskTypePluginInstall:
		return taskstore.LifecycleHelperResolves
	default:
		return taskstore.LifecycleSynchronous
	}
}
