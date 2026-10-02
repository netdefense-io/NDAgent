package tasks

// Reloads after an in-place renewal. A renewed CA or certificate keeps its
// refid, so every service bound to it still names it, but a running service
// keeps the material it loaded: each one is told to load it again, once per
// kind of service, and each consumer gets a trust_reload item. A CA's renewal
// also reaches what uses the certificates it issued. The system trust store
// needs nothing: the CA API's add, set and del rebuild it themselves, detached,
// within about a second.
//
// Each kind of service is one trustReloadUnit, so the action for one can be
// changed without touching the others. The actions were measured on a device,
// except the captive portal's, which comes from OPNsense's source, as does
// what an IPsec reload leaves of established SAs.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// trustReloadUnit is how a changed certificate reaches one kind of service.
type trustReloadUnit struct {
	// Verb is the action a trust_reload item reports.
	Verb string
	// Steps are configctl invocations, run in order until one fails.
	Steps [][]string
	// Finally runs after Steps whatever they did, so a service a step stopped
	// is started again when a later step, or the stop itself, failed.
	Finally [][]string
	// Deferred units run after the SYNC result has been sent: restarting
	// the web GUI cuts the API the SYNC itself talks to.
	Deferred bool
	// IfFailed is what a warning about a failed reload tells the operator to
	// do, when restarting the service is not the whole story.
	IfFailed string
}

// trustReloadUnits are the reload units by consumer kind.
var trustReloadUnits = map[string]trustReloadUnit{
	// Restarts only the instances whose generated configuration changed; the
	// clients of a restarted instance reconnect.
	"openvpn": {Verb: "openvpn configure", Steps: [][]string{{"openvpn", "configure"}}},
	// Never a restart: charon loads the new certificate and established SAs
	// are left alone. OPNsense does not re-authenticate by default, so a rekey
	// keeps the old certificate; the renewed one is presented when a new IKE
	// SA is established.
	"ipsec": {Verb: "ipsec reload", Steps: [][]string{{"ipsec", "reload"}},
		IfFailed: "reload IPsec to load it; the renewed certificate is then presented when a new IKE SA is established, not at a rekey, and established SAs keep running"},
	// A restart (configctl syslog restart) only reloads syslog-ng, which keeps
	// its TLS session and the old certificate; stop and start open a new one.
	// All logging stops for about 0.3 s. start renders the templates itself.
	"syslog": {Verb: "syslog restart", Steps: [][]string{{"syslog", "stop"}}, Finally: [][]string{{"syslog", "start"}},
		IfFailed: "system logging may have been left stopped, or still presents the old certificate: run configctl syslog stop, then configctl syslog start"},
	"captiveportal": {Verb: "captiveportal restart", Steps: [][]string{{"template", "reload", "OPNsense/Captiveportal"}, {"captiveportal", "restart"}}},
	"webgui":        {Verb: "scheduled", Deferred: true},
}

// configctlPath is OPNsense's configd client.
const configctlPath = "/usr/local/sbin/configctl"

// configctlCeiling bounds one configctl invocation.
const configctlCeiling = 3 * time.Minute

// runConfigctlFunc runs one configctl invocation; tests replace it.
var runConfigctlFunc = runConfigctl

// runConfigctl runs configctl with args. Its output is checked and never
// logged or returned: an action's answer is not this agent's to repeat.
func runConfigctl(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, configctlCeiling)
	defer cancel()
	cmd := exec.CommandContext(ctx, configctlPath, args...)
	cmd.Env = DeviceExecEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("configctl %s did not finish: %w", strings.Join(args, " "), ctx.Err())
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("configctl %s exited %d", strings.Join(args, " "), exitErr.ExitCode())
		}
		return fmt.Errorf("configctl %s did not run", strings.Join(args, " "))
	}
	if configdReportedError(out.String()) {
		return fmt.Errorf("configctl %s: configd reported an error", strings.Join(args, " "))
	}
	return nil
}

// configdReportedError reports whether configctl's answer is configd saying
// the action failed: configctl exits 0 either way.
func configdReportedError(answer string) bool {
	for _, failure := range []string{"Execute error", "Action not allowed or missing", "Action not found"} {
		if strings.Contains(answer, failure) {
			return true
		}
	}
	return false
}

// runTrustReloadUnit runs the steps of a unit, then its Finally steps, and
// returns the first failure.
func runTrustReloadUnit(ctx context.Context, unit trustReloadUnit) error {
	var first error
	for _, step := range unit.Steps {
		if err := runConfigctlFunc(ctx, step...); err != nil {
			first = err
			break
		}
	}
	for _, step := range unit.Finally {
		if err := runConfigctlFunc(ctx, step...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// reload tells every service that uses a renewed CA or certificate to load it
// again. It reports whether the web GUI's certificate was renewed: that restart
// runs after the SYNC result is sent.
//
// The units run whatever happens to the task: a dropped connection cancels the
// task, and a reload cut off there (between a stop and its start, say) would
// leave a service down or on the old certificate. Each configctl call is
// bounded on its own. A renewal whose reloads did not finish stays recorded for
// the next pass.
func (r *trustRun) reload() bool {
	type pending struct {
		consumer trustConsumer
		object   string
		// renewals are the renewals that reach the consumer.
		renewals []int
	}
	var byKind = map[string][]*pending{}
	var kinds []string
	byConsumer := map[string]*pending{}

	renewed := append(append([]renewedTrust{}, r.renewedCAs...), r.renewedCerts...)
	keep := make([]bool, len(renewed))
	if len(renewed) > 0 {
		cfg, err := r.deviceConfig()
		if err != nil {
			for i, obj := range renewed {
				keep[i] = true
				r.ok(SyncAPIItemResult{Type: trustTypeReload, Name: obj.Name, Action: "reload", Status: "warning", Code: trustCodeReloadFailed,
					Error: fmt.Sprintf("%s: %q was renewed, but the device configuration could not be read to find what uses it; restart the services that use it",
						trustCodeReloadFailed, obj.Name)})
			}
		} else {
			// A consumer reached by more than one renewal (a CA and a
			// certificate it issued) is reloaded and reported once.
			for i, obj := range renewed {
				isCA := i < len(r.renewedCAs)
				for _, c := range cfg.consumersOf(obj.RefID, isCA) {
					key := c.Kind + "|" + c.UUID + "|" + c.Label
					if p, ok := byConsumer[key]; ok {
						p.renewals = append(p.renewals, i)
						continue
					}
					p := &pending{consumer: c, object: obj.Name, renewals: []int{i}}
					byConsumer[key] = p
					if _, ok := byKind[c.Kind]; !ok {
						kinds = append(kinds, c.Kind)
					}
					byKind[c.Kind] = append(byKind[c.Kind], p)
				}
			}
		}
	}

	ctx := context.WithoutCancel(r.ctx)
	restartWebGUI := r.webGUIOwed
	for _, kind := range kinds {
		unit, known := trustReloadUnits[kind]
		if kind == "" || !known {
			for _, p := range byKind[kind] {
				r.ok(SyncAPIItemResult{Type: trustTypeReload, UUID: p.consumer.UUID, Name: p.consumer.Label, Action: "none", Status: "warning", Code: trustCodeConsumerUnknown,
					Error: fmt.Sprintf("%s: %s uses %q: bound, no known reload: restart to apply", trustCodeConsumerUnknown, p.consumer.Label, p.object)})
			}
			continue
		}
		if unit.Deferred {
			restartWebGUI = true
			for _, p := range byKind[kind] {
				r.ok(SyncAPIItemResult{Type: trustTypeReload, UUID: p.consumer.UUID, Name: p.consumer.Label, Action: unit.Verb, Status: "success", Code: trustCodeReloadScheduled})
			}
			continue
		}
		err := runTrustReloadUnit(ctx, unit)
		unfinished := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
		for _, p := range byKind[kind] {
			item := SyncAPIItemResult{Type: trustTypeReload, UUID: p.consumer.UUID, Name: p.consumer.Label, Action: unit.Verb, Status: "success"}
			if err != nil {
				item.Status, item.Code = "warning", trustCodeReloadFailed
				ifFailed := unit.IfFailed
				if ifFailed == "" {
					ifFailed = "restart it to use the renewed certificate"
				}
				item.Error = fmt.Sprintf("%s: %s did not reload %q (%v); %s", trustCodeReloadFailed, p.consumer.Label, p.object, err, ifFailed)
			}
			r.ok(item)
			if unfinished {
				for _, i := range p.renewals {
					keep[i] = true
				}
			}
		}
		if err != nil {
			logging.Named("SYNC_API").Warnw("Trust: reload failed", "unit", kind, "error", err)
		}
	}

	r.leftCAs, r.leftCerts = nil, nil
	for i, obj := range renewed {
		if !keep[i] {
			continue
		}
		if i < len(r.renewedCAs) {
			r.leftCAs = append(r.leftCAs, obj)
		} else {
			r.leftCerts = append(r.leftCerts, obj)
		}
	}
	r.webGUIRequested = restartWebGUI
	return restartWebGUI
}

// The web GUI restart. Its certificate is read when lighttpd starts, so a
// renewal reaches it only through a restart, and the restart takes down the
// local API: the agent's own channel to OPNsense. It therefore runs after the
// SYNC result has been sent, in a detached helper that outlives the agent, and
// the next SYNC waits, for a bounded time, until the API answers again.

const (
	// webGUIRestartScript is what the detached helper runs. The pause lets
	// the SYNC result go out before anything is restarted.
	webGUIRestartScript = "sleep 3 && exec /usr/local/etc/rc.restart_webgui"

	// webGUIRestartCeiling bounds the wait for the helper to finish.
	webGUIRestartCeiling = 2 * time.Minute
	// webGUIProbeCeiling bounds the wait for the API to answer after it.
	webGUIProbeCeiling = 90 * time.Second
	// webGUIProbeTimeout bounds one probe: a request in flight while lighttpd
	// shuts down hangs until its timeout, so a probe must give up fast.
	webGUIProbeTimeout = 2 * time.Second
	// webGUIProbeInterval spaces the probes.
	webGUIProbeInterval = time.Second
)

// startWebGUIRestartHelper starts the restart helper and returns a function
// that waits for it to exit.
func startWebGUIRestartHelper() (func() error, error) {
	cmd := newDetachedHelperCmd("/bin/sh", "-c", webGUIRestartScript)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}

// webGUIRestarter tracks the restart a SYNC scheduled.
type webGUIRestarter struct {
	mu   sync.Mutex
	done chan struct{}

	start func() (func() error, error)
	// started runs once the helper has started.
	started                                                   func()
	restartCeiling, probeCeiling, probeTimeout, probeInterval time.Duration
}

var webGUIRestart = &webGUIRestarter{
	start:          startWebGUIRestartHelper,
	started:        clearPendingWebGUIRestart,
	restartCeiling: webGUIRestartCeiling,
	probeCeiling:   webGUIProbeCeiling,
	probeTimeout:   webGUIProbeTimeout,
	probeInterval:  webGUIProbeInterval,
}

// schedule starts the restart and, in the background, waits for it to finish
// and for the API to answer again. A restart that does not finish, or an API
// that does not come back, is logged as an ERROR: there is no automatic
// rollback.
func (w *webGUIRestarter) schedule(probe func(context.Context) error) {
	log := logging.Named("SYNC_API")
	w.mu.Lock()
	previous := w.done
	done := make(chan struct{})
	w.done = done
	w.mu.Unlock()

	go func() {
		defer close(done)
		if previous != nil {
			<-previous
		}
		wait, err := w.start()
		if err != nil {
			log.Errorw("Trust: could not start the web GUI restart; restart the web GUI to use its renewed certificate", "error", err)
			return
		}
		log.Infow("Trust: web GUI restart started for its renewed certificate")
		if w.started != nil {
			w.started()
		}

		exited := make(chan error, 1)
		go func() { exited <- wait() }()
		select {
		case err := <-exited:
			if err != nil {
				log.Errorw("Trust: the web GUI restart failed; the web GUI may still serve the old certificate", "error", err)
			}
		case <-time.After(w.restartCeiling):
			log.Errorw("Trust: the web GUI restart did not finish in time", "ceiling", w.restartCeiling)
		}

		deadline := time.Now().Add(w.probeCeiling)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), w.probeTimeout)
			err := probe(ctx)
			cancel()
			if err == nil {
				log.Infow("Trust: the local API answers again after the web GUI restart")
				return
			}
			if time.Now().After(deadline) {
				log.Errorw("Trust: the local API did not answer after the web GUI restart; the web GUI and the API may be down",
					"waited", w.probeCeiling)
				return
			}
			time.Sleep(w.probeInterval)
		}
	}()
}

// wait holds the caller until a scheduled restart has finished and the API
// answers again, or ctx ends. Bounded by the restart's own ceilings.
func (w *webGUIRestarter) wait(ctx context.Context) {
	w.mu.Lock()
	done := w.done
	w.mu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
		w.mu.Lock()
		if w.done == done {
			w.done = nil
		}
		w.mu.Unlock()
	case <-ctx.Done():
	}
}

// localAPIProbe asks the local API a question that costs nothing.
func localAPIProbe(client *opnapi.Client) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := client.GetFirmwareRunning(ctx)
		return err
	}
}
