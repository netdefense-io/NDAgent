//go:build freebsd

package track

import "syscall"

// statfs reads the filesystem path is on: the bytes available to an ordinary
// process, the type (zfs, ufs) and what is mounted (a ZFS dataset such as
// zroot/ROOT/default, or a device).
func statfs(path string) (fsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsInfo{}, err
	}
	avail := int64(st.Bavail) // negative when the reserve is over-used
	if avail < 0 {
		avail = 0
	}
	return fsInfo{
		Avail: avail * int64(st.Bsize),
		Type:  cString(st.Fstypename[:]),
		From:  cString(st.Mntfromname[:]),
	}, nil
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
