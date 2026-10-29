package sshd

import "testing"

func TestParse(t *testing.T) {
	e := parse([]byte("port 22\npermitrootlogin without-password\npasswordauthentication yes\npubkeyauthentication yes\n"))
	if e.Port != "22" || e.PermitRootLogin != "without-password" || e.PasswordAuthentication != "yes" {
		t.Fatalf("%+v", e)
	}
}
