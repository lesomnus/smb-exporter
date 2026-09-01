package smb

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// SmbstatusArgs asks only for sessions; the share and lock tables are not used.
var SmbstatusArgs = []string{"-b"}

var reIPv4 = regexp.MustCompile(`ipv4:([0-9.]+):\d+`)

// ParseSmbstatus reads `smbstatus -b` output and maps client address to account.
//
// A row looks like:
//
//	332882  hojoon.lee   hojoon.lee   10.1.2.100 (ipv4:10.1.2.100:43880)  SMB3_11  ...
//
// Header and separator lines carry no `ipv4:` and are skipped by that alone, so
// this does not depend on the column layout staying put.
func ParseSmbstatus(r io.Reader) (map[string]Session, error) {
	out := map[string]Session{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		m := reIPv4.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := m[1]
		// One address can hold several sessions; they are the same person, so
		// first wins and later rows are redundant rather than conflicting.
		if _, ok := out[ip]; !ok {
			out[ip] = Session{User: f[1], ClientIP: ip}
		}
	}
	return out, sc.Err()
}
