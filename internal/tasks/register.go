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

	// Register firmware upgrade handler
	dispatcher.RegisterHandler(network.TaskTypeFirmwareUpgrade, HandleFirmwareUpgrade)
}

// LifecycleFor returns the taskstore Lifecycle category for a given task
// type. The dispatcher consults this at Begin time to record how the
// connect-time drain should treat any row left IN_PROGRESS — see the
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
	case network.TaskTypeFirmwareUpgrade:
		// Not what decides a FIRMWARE_UPGRADE row. The drain skips the type
		// whatever lifecycle a row carries, and the firmware reconciler
		// (internal/core) resolves it from the device's state, because a row can
		// outlive its handler on any path: the update is a detached OPNsense
		// process, a package in the run can restart the agent, and the box
		// reboots. This value is what an agent that predates the reconciler does
		// with such a row (completes it when it returns), which is why it is kept.
		return taskstore.LifecycleRestartCompletes
	default:
		return taskstore.LifecycleSynchronous
	}
}
