//go:build unix

package update

import (
	"os"
	"runtime"
	"syscall"
)

// ownerOf reports who owns path, so root can hand a file it wrote back to the
// service account.
func ownerOf(path string) (uid, gid int, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func runtimeArch() string { return runtime.GOARCH }
func runtimeOS() string   { return runtime.GOOS }
