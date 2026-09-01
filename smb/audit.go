package smb

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ParseAuditLine reads one full_audit record.
//
// With `full_audit:prefix = %u|%I|%S` a record is
//
//	  taehyeon.kim|10.1.2.136|simulation|create_file|ok|0x80000000|file|open|/srv/data/...
//
// preceded by a Samba log header line, which has no `|` and is skipped. The
// path is deliberately not returned: it is the largest field and nothing here
// wants it.
func ParseAuditLine(line string) (Op, bool) {
	if !strings.Contains(line, "|") {
		return Op{}, false
	}
	f := strings.Split(strings.TrimSpace(line), "|")
	if len(f) < 5 || f[0] == "" {
		return Op{}, false
	}
	// Only successes are configured (`full_audit:failure = none`), but do not
	// assume it: a failed open is not a file that was read.
	if f[4] != "ok" {
		return Op{}, false
	}
	return Op{User: f[0], Share: f[2], Op: f[3]}, true
}

// AuditCounter follows the full_audit log and keeps counts, never lines.
//
// The log rotates fast — Samba renames it aside on `max log size` and during a
// scan of many small files that can happen within a minute — so the follower
// reopens when the file shrinks or is replaced. Records written during the
// swap are lost; these are rate counters, not an audit trail, so that is
// acceptable and is the reason this is not the place to look for "who deleted
// this file".
type AuditCounter struct {
	path string

	mu sync.Mutex
	n  map[Op]int64
}

func NewAuditCounter(path string) *AuditCounter {
	return &AuditCounter{path: path, n: map[Op]int64{}}
}

// Drain returns the counts accumulated since the last call and resets them.
func (c *AuditCounter) Drain() map[Op]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.n
	c.n = map[Op]int64{}
	return out
}

func (c *AuditCounter) add(op Op) {
	c.mu.Lock()
	c.n[op]++
	c.mu.Unlock()
}

// Follow reads the log until ctx is done. It starts at the end: history is not
// interesting and on a busy server the backlog would be counted as if it had
// just happened.
func (c *AuditCounter) Follow(ctx context.Context) error {
	var (
		f  *os.File
		br *bufio.Reader
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	open := func(fromEnd bool) error {
		if f != nil {
			f.Close()
			f = nil
		}
		v, err := os.Open(c.path)
		if err != nil {
			return err
		}
		if fromEnd {
			if _, err := v.Seek(0, io.SeekEnd); err != nil {
				v.Close()
				return err
			}
		}
		f = v
		br = bufio.NewReaderSize(v, 64*1024)
		return nil
	}

	fromEnd := true
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if f == nil {
			if err := open(fromEnd); err != nil {
				// The log may not exist yet; keep trying rather than dying.
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(2 * time.Second):
				}
				continue
			}
			fromEnd = false
		}

		line, err := br.ReadString('\n')
		if len(line) > 0 {
			if op, ok := ParseAuditLine(line); ok {
				c.add(op)
			}
			continue
		}
		if err != nil && err != io.EOF {
			f.Close()
			f = nil
			continue
		}

		// At EOF: has the file been rotated away under us?
		if rotated(f, c.path) {
			f.Close()
			f = nil
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// rotated reports whether the open handle no longer refers to the file at path,
// or the file was truncated behind our offset.
func rotated(f *os.File, path string) bool {
	cur, err := f.Stat()
	if err != nil {
		return true
	}
	next, err := os.Stat(path)
	if err != nil {
		return false // gone for a moment; keep the handle
	}
	if !os.SameFile(cur, next) {
		return true
	}
	off, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return true
	}
	return cur.Size() < off
}
