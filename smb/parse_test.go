package smb_test

import (
	"strings"
	"testing"

	"github.com/lesomnus/smb-exporter/smb"
)

// Captured from a live server (Samba 4.23, Linux 7.0). Kept verbatim: the
// point of these tests is that the real format keeps parsing.
const ssOut = `Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0          10.1.62.8:445    10.1.2.192:59116
	 cubic wscale:10,10 rto:201 rtt:0.301/0.419 ato:40 mss:1448 cwnd:10 bytes_sent:9573961808 bytes_retrans:2231253 bytes_acked:9571730555 bytes_received:527952471 segs_out:8374997 segs_in:1711467
0      0          10.1.62.8:445    10.1.2.226:37662
	 cubic wscale:10,10 rto:204 rtt:3.077/5.795 ato:40 mss:1448 cwnd:10 bytes_sent:2149789 bytes_acked:2149789 bytes_received:819458 segs_out:6424 segs_in:9841
0      0          10.1.62.8:445   10.250.0.20:60833
	 cubic wscale:10,10 rto:210 rtt:1.1/0.5 ato:40 mss:1448 cwnd:10 segs_out:3 segs_in:2
`

func TestParseSs(t *testing.T) {
	conns, err := smb.ParseSs(strings.NewReader(ssOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 3 {
		t.Fatalf("want 3 conns, got %d: %+v", len(conns), conns)
	}
	if conns[0].ClientIP != "10.1.2.192" || conns[0].ClientPort != "59116" {
		t.Errorf("peer: %+v", conns[0])
	}
	if conns[0].BytesSent != 9573961808 || conns[0].BytesRecv != 527952471 {
		t.Errorf("bytes: %+v", conns[0])
	}
	// A socket that has not moved data yet has no bytes_* at all; it must still
	// be reported so the connection count is right.
	if conns[2].ClientIP != "10.250.0.20" || conns[2].BytesSent != 0 {
		t.Errorf("idle conn: %+v", conns[2])
	}
}

const statusOut = `
Samba version 4.23.6
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing
------------------------------------------------------------------------------------------------------------------------
332882  hojoon.lee   hojoon.lee   10.1.2.100 (ipv4:10.1.2.100:43880)        SMB3_11           -                    partial(AES-128-CMAC)
323651  beomhyuk.koo beomhyuk.koo 10.1.2.85 (ipv4:10.1.2.85:53626)          SMB3_11           -                    partial(AES-128-CMAC)
385196  jaehyeon.park jaehyeon.park 10.1.4.43 (ipv4:10.1.4.43:46568)        SMB3_11           -                    partial(AES-128-GMAC)
`

func TestParseSmbstatus(t *testing.T) {
	got, err := smb.ParseSmbstatus(strings.NewReader(statusOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 sessions, got %d: %+v", len(got), got)
	}
	if got["10.1.2.100"].User != "hojoon.lee" {
		t.Errorf("user: %+v", got["10.1.2.100"])
	}
	if _, ok := got["10.1.4.43"]; !ok {
		t.Errorf("missing session: %+v", got)
	}
}

func TestParseAuditLine(t *testing.T) {
	line := "  taehyeon.kim|10.1.2.136|simulation|create_file|ok|0x80000000|file|open|/srv/data/teams/simulation/a/b/grasp.json"
	op, ip, ok := smb.ParseAuditLine(line)
	if !ok {
		t.Fatal("want parsed")
	}
	if op.User != "taehyeon.kim" || op.Share != "simulation" || op.Op != "create_file" {
		t.Errorf("got %+v", op)
	}
	// The client address is what lets a standalone deployment attribute
	// traffic without reading smbd's lock directory.
	if ip != "10.1.2.136" {
		t.Errorf("client address: %q", ip)
	}

	// The header line Samba writes before every record carries no fields.
	if _, _, ok := smb.ParseAuditLine("[2026/09/02 00:59:29.692874,  1] source3/modules/vfs_full_audit.c:637(do_log)"); ok {
		t.Error("header must not parse")
	}
	// A failed operation is not a file that was read.
	if _, _, ok := smb.ParseAuditLine("  a|1.2.3.4|s|create_file|fail|x|file|open|/p"); ok {
		t.Error("failure must not count")
	}
}

func TestCollectorFirstSightIsZero(t *testing.T) {
	c := smb.NewCollector()
	s1 := &smb.Sample{
		Conns:    []smb.Conn{{ClientIP: "10.0.0.1", ClientPort: "1", BytesSent: 1000}},
		Sessions: map[string]smb.Session{"10.0.0.1": {User: "alice", ClientIP: "10.0.0.1"}},
	}
	d1 := c.Apply(s1)
	if len(d1) != 1 || d1[0].BytesSent != 0 {
		t.Fatalf("first sight must contribute nothing, got %+v", d1)
	}

	s2 := &smb.Sample{
		Conns:    []smb.Conn{{ClientIP: "10.0.0.1", ClientPort: "1", BytesSent: 1500}},
		Sessions: s1.Sessions,
	}
	d2 := c.Apply(s2)
	if len(d2) != 1 || d2[0].BytesSent != 500 || d2[0].User != "alice" {
		t.Fatalf("want delta 500 for alice, got %+v", d2)
	}

	// Port reuse: the counter restarts, so the current value is the new
	// connection's own total rather than a negative delta.
	s3 := &smb.Sample{
		Conns:    []smb.Conn{{ClientIP: "10.0.0.1", ClientPort: "1", BytesSent: 20}},
		Sessions: s1.Sessions,
	}
	d3 := c.Apply(s3)
	if d3[0].BytesSent != 20 {
		t.Fatalf("want 20 on counter reset, got %+v", d3)
	}
}

func TestUnknownUser(t *testing.T) {
	c := smb.NewCollector()
	s := &smb.Sample{
		Conns:    []smb.Conn{{ClientIP: "10.0.0.9", ClientPort: "2", BytesSent: 5}},
		Sessions: map[string]smb.Session{},
	}
	d := c.Apply(s)
	if len(d) != 1 || d[0].User != "unknown" {
		t.Fatalf("connection without a session must be attributed to unknown, got %+v", d)
	}
}

func TestSessionMapFromAudit(t *testing.T) {
	m := smb.NewSessionMap()
	m.Put("10.1.2.136", "taehyeon.kim")
	if m.Snapshot()["10.1.2.136"].User != "taehyeon.kim" {
		t.Fatal("put/snapshot")
	}
	// An authoritative source wins.
	m.Merge(map[string]smb.Session{"10.1.2.136": {User: "real.name", ClientIP: "10.1.2.136"}})
	if m.Snapshot()["10.1.2.136"].User != "real.name" {
		t.Error("merge must override")
	}
	// A client with no connection left is forgotten.
	m.Retain([]smb.Conn{{ClientIP: "10.9.9.9"}})
	if len(m.Snapshot()) != 0 {
		t.Error("retain must drop stale entries")
	}
}
