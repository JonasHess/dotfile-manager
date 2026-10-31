package roles

import "testing"

const testFingerprint = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg"

func TestScanAcceptedJournal(t *testing.T) {
	log := "2026-01-02T03:04:05+0100 example-host sshd[1234]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 " + testFingerprint + "\n"
	when, ok := scanAccepted(log, testFingerprint)
	if !ok || when != "2026-01-02T03:04:05+0100" {
		t.Fatalf("journal line: got %q, %v", when, ok)
	}
}

func TestScanAcceptedMacOSUnifiedLog(t *testing.T) {
	log := `Timestamp                       Thread     Type        Activity             PID    TTL
2026-01-02 03:04:05.123456+0100 0x1a2b3c   Info        0x0                  4242   0    sshd-session: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 ` + testFingerprint + `
`
	when, ok := scanAccepted(log, testFingerprint)
	if !ok || when != "2026-01-02 03:04:05.123456+0100" {
		t.Fatalf("unified log line: got %q, %v", when, ok)
	}
}

func TestScanAcceptedIgnoresOtherKeys(t *testing.T) {
	log := "2026-01-02T03:04:05+0100 example-host sshd[1234]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:SomeOtherKey\n"
	if _, ok := scanAccepted(log, testFingerprint); ok {
		t.Fatal("matched a login with a different key")
	}
}
