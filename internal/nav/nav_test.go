package nav

import (
	"bytes"
	"testing"
)

func TestRequestCookie(t *testing.T) {
	raw := "0123456789abcdefghijklmn"
	if got := requestCookie(raw); !bytes.Equal(got, []byte(raw)) {
		t.Fatalf("raw: %q", got)
	}
	if got := requestCookie("303132333435363738396162636465666768696a6b6c6d6e"); !bytes.Equal(got, []byte(raw)) {
		t.Fatalf("hex: %q", got)
	}
	for _, bad := range []string{"", "short", raw + "x", "zz" + raw[2:]} {
		if bad == "zz"+raw[2:] {
			continue // 24 raw bytes that are not hex are a valid raw cookie
		}
		if requestCookie(bad) != nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
