//go:build !unix

package update

import "runtime"

// ownerOf has no meaning where files are not owned by a numeric uid/gid.
func ownerOf(string) (uid, gid int, ok bool) { return 0, 0, false }

func runtimeArch() string { return runtime.GOARCH }
func runtimeOS() string   { return runtime.GOOS }
