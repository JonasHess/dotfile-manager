package bundle

import (
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Files{"a": []byte("hello"), "b": []byte("world")}
	enc, err := Encrypt(in, []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsAge(enc) {
		t.Fatal("missing age header")
	}
	out, err := Decrypt(enc, []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out["a"]) != "hello" || string(out["b"]) != "world" || len(out) != 2 {
		t.Fatalf("got %v", out)
	}
	if _, err := Decrypt(enc, []byte("nope")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected wrong passphrase, got %v", err)
	}
}
