package smb

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// SsArgs is the command that yields the byte counters.
//
// `-i` is what carries them: they come from the kernel's tcp_info, not from
// /proc/net/tcp, which has no byte counters at all.
var SsArgs = []string{"-tin", "state", "established", "( sport = :445 )"}

var (
	rePeer  = regexp.MustCompile(`^\s*\d+\s+\d+\s+\S+:445\s+([0-9a-fA-F.:]+):(\d+)`)
	reSent  = regexp.MustCompile(`bytes_sent:(\d+)`)
	reRecv  = regexp.MustCompile(`bytes_received:(\d+)`)
)

// ParseSs reads `ss -tin` output.
//
// The format is two lines per socket: an address line, then an indented line of
// space separated key:value pairs. A socket with no traffic yet has no
// bytes_sent at all, so absence is zero rather than an error.
func ParseSs(r io.Reader) ([]Conn, error) {
	out := []Conn{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var cur *Conn
	for sc.Scan() {
		line := sc.Text()
		if m := rePeer.FindStringSubmatch(line); m != nil {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &Conn{ClientIP: m[1], ClientPort: m[2]}
			continue
		}
		if cur == nil || !strings.Contains(line, "bytes_") {
			continue
		}
		if m := reSent.FindStringSubmatch(line); m != nil {
			cur.BytesSent, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reRecv.FindStringSubmatch(line); m != nil {
			cur.BytesRecv, _ = strconv.ParseInt(m[1], 10, 64)
		}
		out = append(out, *cur)
		cur = nil
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out, sc.Err()
}
