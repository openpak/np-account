package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"openpak/np-account/internal/onlineid"
	"testing"
	"time"
)

func TestAuthenticatedFirmwareEnvelope(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s, _ := New(key, func() time.Time { return now })
	b, e := s.Issue(Identity{AccountID: "account-one", LinkID: "link-one", OnlineID: "AndroidTest", Country: "us", Service: "IV0001-NPXS01001_00", ConsoleID: "console"}, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	cursor := 10
	types := []uint16{8, 1, 7, 7, 2, 4, 8, 4, 8, 0x3011, 1, 7}
	sizes := []int{20, 4, 8, 8, 8, 32, 4, 4, 24, 4, 4, 8}
	for i, typ := range types {
		if binary.BigEndian.Uint16(b[cursor:]) != typ || int(binary.BigEndian.Uint16(b[cursor+2:])) != sizes[i] {
			t.Fatalf("firmware field %d", i)
		}
		v := b[cursor+4 : cursor+4+sizes[i]]
		if i == 2 || i == 3 {
			timestamp := binary.BigEndian.Uint64(v)
			tick := timestamp*1000 + 0xdcbffeff2bc000
			if tick+0xff1fe2ffc59c6000 >= 0xb3625a1cbe000 {
				t.Fatal("firmware RTC rejects timestamp")
			}
		}
		if i == 4 && binary.BigEndian.Uint64(v) != onlineid.AccountID("account-one") {
			t.Fatal("native/ticket ID mismatch")
		}
		cursor += 4 + sizes[i]
	}
	id, e := s.Verify(b)
	if e != nil || id.OnlineID != "AndroidTest" {
		t.Fatalf("verify: %+v %v", id, e)
	}
	extended := append(append([]byte(nil), b...), []byte("device-extension")...)
	if _, e = s.Verify(extended); e != nil {
		t.Fatal("firmware extension rejected", e)
	}
	// Every signed byte is protected, including identity, times and service.
	for i := 0; i < len(b); i++ {
		bad := append([]byte(nil), b...)
		bad[i] ^= 1
		if _, e = s.Verify(bad); e == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	for n := 0; n < len(b); n++ {
		if _, e = s.Verify(b[:n]); e == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	now = now.Add(time.Hour)
	if _, e = s.Verify(b); e == nil {
		t.Fatal("expired ticket accepted")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s2, _ := New(other, nil)
	if _, e = s2.Verify(b); e == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestAvatarCapabilityBoundsAndExpiry(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s, _ := New(key, func() time.Time { return now })
	id := "11111111-2222-4333-8444-555555555555"
	cap := s.AvatarCapability(id)
	if len("http://avatar.np.community.playstation.net/a/"+cap+".png") > 127 {
		t.Fatal("URL too long for firmware")
	}
	if got, e := s.VerifyAvatar(cap); e != nil || got != id {
		t.Fatal(got, e)
	}
	for i := 0; i < len(cap); i++ {
		b := []byte(cap)
		b[i] = '!'
		if _, e := s.VerifyAvatar(string(b)); e == nil {
			t.Fatal("tampered avatar capability accepted")
		}
	}
	now = now.Add(26 * time.Hour)
	if _, e := s.VerifyAvatar(cap); e == nil {
		t.Fatal("expired avatar URL accepted")
	}
}

func TestBirthFields(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	st, dob := birthFields("1990-01-01", now)
	if st[0] != 36 || st[3] != 0x80 || binary.BigEndian.Uint64(dob) != 631152000000 {
		t.Fatalf("status %x dob %x", st, dob)
	}
	if st, _ := birthFields("1990-12-31", now); st[0] != 35 {
		t.Fatalf("age before birthday: %d", st[0])
	}
	for _, bad := range []string{"", "x", "2030-01-01"} {
		if st, dob := birthFields(bad, now); binary.BigEndian.Uint32(st) != 0 || binary.BigEndian.Uint64(dob) != 0 {
			t.Fatalf("%q must leave status and date zero", bad)
		}
	}
}
