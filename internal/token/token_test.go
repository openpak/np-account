package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef-test"

func TestIssueVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(testKey, func() time.Time { return now })
	other := New(testKey+"x", func() time.Time { return now })
	good := s.Issue(KindAccess, Claims{AccountID: "a1", OnlineID: "Leia"}, time.Hour)

	tamper := func(tok string) string { return tok[:5] + "A" + tok[6:] }
	for _, tc := range []struct {
		name string
		kind string
		tok  string
		now  time.Time
		want error
	}{
		{"valid", KindAccess, good, now, nil},
		{"wrong kind", KindGrant, good, now, ErrInvalid},
		{"tampered", KindAccess, tamper(good), now, ErrInvalid},
		{"no dot", KindAccess, "abc", now, ErrInvalid},
		{"empty", KindAccess, "", now, ErrInvalid},
		{"expired", KindAccess, good, now.Add(time.Hour), ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(testKey, func() time.Time { return tc.now })
			c, err := v.Verify(tc.kind, tc.tok)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err == nil && (c.AccountID != "a1" || c.OnlineID != "Leia" || c.JTI == "") {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
	if _, err := other.Verify(KindAccess, good); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another key must not verify: %v", err)
	}
	if a, b := s.Issue(KindGrant, Claims{}, time.Minute), s.Issue(KindGrant, Claims{}, time.Minute); a == b {
		t.Fatal("tokens must be unique")
	}
}

func TestIDToken(t *testing.T) {
	s := New(testKey, nil)
	tok, err := s.IDToken(map[string]any{"online_id": "Leia", "auth_time": 5})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not a compact JWT: %s", tok)
	}
	m, err := s.VerifyIDToken(tok)
	if err != nil || m["online_id"] != "Leia" {
		t.Fatalf("verify: %v %v", m, err)
	}
	if _, err := s.VerifyIDToken(tok + "x"); err == nil {
		t.Fatal("tampered id_token verified")
	}
	if _, err := New(testKey+"x", nil).VerifyIDToken(tok); err == nil {
		t.Fatal("another key verified")
	}
}
