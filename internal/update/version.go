package update

import (
	"strconv"
	"strings"
)

// IsRelease reports whether v looks like something that came out of a release
// build rather than `go build` on a laptop or the Dockerfile's default.
//
// An untagged build is never replaced automatically: whoever put it there
// meant to, and clobbering it with a published release would lose their work.
func IsRelease(v string) bool {
	_, ok := parse(v)
	return ok
}

// Compare orders two versions the way semver does, and reports false when
// either side is not orderable — an untagged build, or a tag that is not a
// version at all. Callers must not fall back to string comparison in that
// case: "dev" sorts after "1.9.0" and would look like a downgrade.
//
// Leading zeros are tolerated, so the v1.0.001 style of tag orders correctly
// against 1.0.1 rather than being rejected outright.
func Compare(a, b string) (int, bool) {
	va, ok := parse(a)
	if !ok {
		return 0, false
	}
	vb, ok := parse(b)
	if !ok {
		return 0, false
	}
	return va.compare(vb), true
}

// Newer reports whether candidate is a later version than current.
func Newer(current, candidate string) (bool, bool) {
	c, ok := Compare(current, candidate)
	return c < 0, ok
}

type version struct {
	nums []int
	pre  []string // pre-release identifiers, empty for a final release
}

func parse(s string) (version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return version{}, false
	}

	// Build metadata never affects ordering.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}

	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if rest := s[i+1:]; rest != "" {
			pre = strings.Split(rest, ".")
		}
		s = s[:i]
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return version{}, false
	}

	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		// strconv.Atoi accepts a leading "+"/"-" and we have already stripped
		// the meaningful ones, so reject anything non-numeric explicitly.
		if p == "" || strings.ContainsFunc(p, func(r rune) bool { return r < '0' || r > '9' }) {
			return version{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return version{}, false
		}
		nums = append(nums, n)
	}
	return version{nums: nums, pre: pre}, true
}

func (a version) compare(b version) int {
	for i := 0; i < len(a.nums) || i < len(b.nums); i++ {
		x, y := at(a.nums, i), at(b.nums, i)
		if x != y {
			return sign(x - y)
		}
	}

	// A pre-release sorts before the final release it leads up to.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}

	for i := 0; i < len(a.pre) || i < len(b.pre); i++ {
		if i >= len(a.pre) {
			return -1 // fewer identifiers sorts first
		}
		if i >= len(b.pre) {
			return 1
		}
		if c := comparePre(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	return 0
}

// comparePre follows semver: numeric identifiers compare numerically and sort
// below alphanumeric ones.
//
// Mixed identifiers are compared naturally rather than byte by byte, so rc2
// sorts before rc10. Strict semver would call rc10 the older of the two, which
// is never what someone tagging release candidates meant.
func comparePre(a, b string) int {
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	aNum, bNum := errA == nil, errB == nil

	switch {
	case aNum && bNum:
		return sign(na - nb)
	case aNum:
		return -1
	case bNum:
		return 1
	default:
		return compareNatural(a, b)
	}
}

// compareNatural orders two strings treating runs of digits as numbers.
func compareNatural(a, b string) int {
	for len(a) > 0 && len(b) > 0 {
		if isDigit(a[0]) && isDigit(b[0]) {
			ra, na := leadingDigits(a)
			rb, nb := leadingDigits(b)
			if na != nb {
				return sign(na - nb)
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return sign(int(a[0]) - int(b[0]))
		}
		a, b = a[1:], b[1:]
	}
	return sign(len(a) - len(b))
}

func leadingDigits(s string) (rest string, n int) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	n, _ = strconv.Atoi(s[:i])
	return s[i:], n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func at(xs []int, i int) int {
	if i < len(xs) {
		return xs[i]
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
