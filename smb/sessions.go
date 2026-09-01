package smb

import "sync"

// SessionMap maps a client address to the account behind it.
//
// There are two ways to learn this and they are not equally available:
//
//   - `smbstatus` is authoritative, but it reads Samba's *lock directory*
//     (`/run/samba` by default), which is private to the smbd container. A
//     process outside that container cannot see it, so this only works when
//     the exporter runs beside smbd.
//   - The full_audit stream carries `%u|%I|%S` on every record, so the mapping
//     falls out of traffic the client is already generating. This works from
//     anywhere the log file is readable, which is what makes a standalone
//     deployment possible.
//
// The audit-derived map only knows accounts that have touched a file. An
// authenticated but idle session is missing from it. That is acceptable here:
// a client moving bytes is by definition doing operations, and a client moving
// nothing contributes nothing to attribute.
type SessionMap struct {
	mu sync.RWMutex
	m  map[string]Session
}

func NewSessionMap() *SessionMap {
	return &SessionMap{m: map[string]Session{}}
}

func (s *SessionMap) Put(ip string, user string) {
	if ip == "" || user == "" {
		return
	}
	s.mu.Lock()
	s.m[ip] = Session{User: user, ClientIP: ip}
	s.mu.Unlock()
}

// Merge overlays an authoritative map, which wins over anything learned from
// the audit stream.
func (s *SessionMap) Merge(in map[string]Session) {
	s.mu.Lock()
	for k, v := range in {
		s.m[k] = v
	}
	s.mu.Unlock()
}

func (s *SessionMap) Snapshot() map[string]Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Session, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// Retain drops entries whose address no longer has a connection, so a client
// that disconnects does not hold its account in memory forever.
func (s *SessionMap) Retain(conns []Conn) {
	live := make(map[string]struct{}, len(conns))
	for _, c := range conns {
		live[c.ClientIP] = struct{}{}
	}
	s.mu.Lock()
	for k := range s.m {
		if _, ok := live[k]; !ok {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}
