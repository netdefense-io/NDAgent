//go:build !freebsd

package track

import "syscall"

// statfs reads the free space of the filesystem path is on. Off FreeBSD (a
// development machine, CI) the type and what is mounted are not read: nothing
// there is a ZFS root the agent upgrades.
func statfs(path string) (fsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsInfo{}, err
	}
	avail := int64(st.Bavail)
	if avail < 0 {
		avail = 0
	}
	return fsInfo{Avail: avail * int64(st.Bsize)}, nil
}
