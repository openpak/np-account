package onlineid

import "testing"

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"abc", true}, {"Leia_B-1", true}, {"A234567890123456", true},
		{"ab", false}, {"A2345678901234567", false}, {"1abc", false},
		{"_abc", false}, {"a b", false}, {"añb", false}, {"", false},
	} {
		if got := Valid(tc.in); got != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFromDisplayName(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Leia Organa", "Leia_Organa", true},
		{"9lives", "P9lives", true},
		{"a", "a__", true},
		{"averyveryverylongdisplayname", "averyveryverylon", true},
		{"日本語", "", false},
		{"", "", false},
	} {
		got, ok := FromDisplayName(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("FromDisplayName(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestUserID(t *testing.T) {
	a, b := UserID("link-1"), UserID("link-2")
	if a == b || a != UserID("link-1") {
		t.Fatalf("user_id must be stable and per-link: %s %s", a, b)
	}
	if len(a) == 0 || a[0] == '-' {
		t.Fatalf("user_id must be a positive decimal: %s", a)
	}
}
