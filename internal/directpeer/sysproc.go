package directpeer

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// sysProcAttr is how the companion process is set apart from the agent: a
// session of its own, and, when the agent is root, an unprivileged user with
// no group but its own.
func (st *Starter) sysProcAttr() (*syscall.SysProcAttr, error) {
	euid, lookup := os.Geteuid, user.Lookup
	if st.euid != nil {
		euid = st.euid
	}
	if st.lookupUser != nil {
		lookup = st.lookupUser
	}
	runAs := st.RunAs
	if runAs == "" {
		runAs = DefaultRunAs
	}
	cred, err := credentialFor(runAs, euid(), lookup)
	if err != nil {
		return nil, err
	}
	attr := &syscall.SysProcAttr{Setsid: true, Credential: cred}
	endWithParent(attr)
	return attr, nil
}

// credentialFor is the identity the companion runs under. An agent that is
// not root cannot change it and runs the companion as itself (a development
// machine). An agent that is root never runs the companion as root: a user
// that cannot be found, or that is root or in root's group, is an error.
func credentialFor(name string, euid int, lookup func(string) (*user.User, error)) (*syscall.Credential, error) {
	if euid != 0 {
		return nil, nil
	}
	u, err := lookup(name)
	if err != nil {
		return nil, fmt.Errorf("user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has no numeric user id", name)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has no numeric group id", name)
	}
	if uid == 0 || gid == 0 {
		return nil, fmt.Errorf("user %q is root or in root's group", name)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}, nil
}
