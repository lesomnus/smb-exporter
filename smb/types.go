package smb

// Conn is one established TCP connection to the SMB port, as reported by `ss`.
//
// BytesSent is server -> client, which is what a dataset pull looks like.
// The counters live in the socket, so they vanish when the connection closes;
// see Collector for how that is turned into a monotonic total.
type Conn struct {
	ClientIP   string
	ClientPort string
	BytesSent  int64
	BytesRecv  int64
}

func (c Conn) Key() string { return c.ClientIP + ":" + c.ClientPort }

// Session is one SMB session, as reported by `smbstatus`. It is the only thing
// that maps a client address to a person.
type Session struct {
	User     string
	ClientIP string
}

// Op is a counted file operation from the full_audit VFS module.
//
// Only the count is kept. The audit stream is a line per file open, which on a
// scan of many small files reaches hundreds of lines per second; storing them
// is what this exporter exists to avoid.
type Op struct {
	User  string
	Share string
	Op    string
}

// Sample is one poll of the socket and session tables.
type Sample struct {
	Conns    []Conn
	Sessions map[string]Session // keyed by client IP
}

// UserOf returns the account behind a connection, or "unknown" when the socket
// has no session yet (a client that connected but has not authenticated).
func (s *Sample) UserOf(c Conn) string {
	if v, ok := s.Sessions[c.ClientIP]; ok && v.User != "" {
		return v.User
	}
	return "unknown"
}
