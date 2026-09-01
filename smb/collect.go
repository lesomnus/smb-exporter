package smb

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Delta is the traffic attributed to one account since the previous poll.
type Delta struct {
	User      string
	BytesSent int64
	BytesRecv int64
	Conns     int64
}

// Collector turns per-socket cumulative counters into per-account deltas.
//
// The counters belong to the socket, so a closed connection takes its total
// with it. Two consequences, both deliberate:
//
//   - A connection seen for the first time contributes 0, not its whole
//     history. Otherwise every exporter restart would publish a spike of
//     traffic that did not happen in that interval.
//   - Traffic on a connection that opens and closes entirely between two polls
//     is never seen. SMB sessions here last hours, so this loses little, but it
//     does mean the totals are a floor rather than an exact figure.
type Collector struct {
	prev map[string]Conn
}

func NewCollector() *Collector { return &Collector{prev: map[string]Conn{}} }

func (c *Collector) Apply(s *Sample) []Delta {
	next := make(map[string]Conn, len(s.Conns))
	acc := map[string]*Delta{}

	get := func(user string) *Delta {
		if v, ok := acc[user]; ok {
			return v
		}
		v := &Delta{User: user}
		acc[user] = v
		return v
	}

	for _, cur := range s.Conns {
		k := cur.Key()
		next[k] = cur
		d := get(s.UserOf(cur))
		d.Conns++

		p, ok := c.prev[k]
		if !ok {
			continue // first sight; see the type comment
		}
		// A counter that went backwards means the port was reused by a new
		// connection, so the current value is that connection's own total.
		if cur.BytesSent < p.BytesSent || cur.BytesRecv < p.BytesRecv {
			d.BytesSent += cur.BytesSent
			d.BytesRecv += cur.BytesRecv
			continue
		}
		d.BytesSent += cur.BytesSent - p.BytesSent
		d.BytesRecv += cur.BytesRecv - p.BytesRecv
	}

	c.prev = next

	out := make([]Delta, 0, len(acc))
	for _, v := range acc {
		out = append(out, *v)
	}
	return out
}

// Source runs the two commands that make a Sample.
//
// Shelling out is on purpose: the byte counters come from the kernel's
// inet_diag netlink API and `ss` is the tool that already speaks it, exactly as
// tegra-exporter defers to tegrastats.
type Source struct {
	Ss         []string
	Smbstatus  []string
}

// DefaultSource omits smbstatus: the deployment that works without disturbing
// a running smbd cannot reach its lock directory. Set it explicitly when the
// exporter runs beside smbd.
func DefaultSource() Source {
	return Source{Ss: append([]string{"ss"}, SsArgs...)}
}

func (s Source) Sample(ctx context.Context) (*Sample, error) {
	so, err := run(ctx, s.Ss)
	if err != nil {
		return nil, fmt.Errorf("run ss: %w", err)
	}
	conns, err := ParseSs(bytes.NewReader(so))
	if err != nil {
		return nil, fmt.Errorf("parse ss: %w", err)
	}

	// smbstatus is optional. It reads Samba's lock directory, which is private
	// to the smbd container, so a standalone deployment leaves this unset and
	// takes the mapping from the audit stream instead.
	sessions := map[string]Session{}
	if len(s.Smbstatus) > 0 {
		to, err := run(ctx, s.Smbstatus)
		if err != nil {
			return nil, fmt.Errorf("run smbstatus: %w", err)
		}
		sessions, err = ParseSmbstatus(bytes.NewReader(to))
		if err != nil {
			return nil, fmt.Errorf("parse smbstatus: %w", err)
		}
	}

	return &Sample{Conns: conns, Sessions: sessions}, nil
}

func run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, errb.String())
	}
	return out.Bytes(), nil
}
