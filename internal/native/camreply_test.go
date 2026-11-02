package native_test

// Firmware-contract tests for the CAM authenticate reply.
//
// The Account Information loader (regcam_plugin 4.93 FUN_0006b1e0) parses the
// reply with FUN_000dd9ac (0x5e account), FUN_000d8f58 (0x5f settings) and
// FUN_000da04c (0x16 service list). Any element below the minimum length, or a
// missing 0x15/0x7d/0x7e inside a service entry, aborts the load and Account
// Information exits silently. These tests pin the exact parser requirements
// against the served bytes. Verified 2026-10-27 via Pier + firmware RE.

import (
	"encoding/binary"
	"net/url"
	"testing"
)

// tlv splits tag-1 list bodies and plain element streams into (tag, value).
func elems(t *testing.T, b []byte) (tags []uint16, vals [][]byte) {
	t.Helper()
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatalf("truncated element header (%d bytes left)", len(b))
		}
		tag := binary.BigEndian.Uint16(b[0:2])
		ln := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+ln {
			t.Fatalf("tag 0x%x claims %d bytes, %d left", tag, ln, len(b)-4)
		}
		tags = append(tags, tag)
		vals = append(vals, b[4:4+ln])
		b = b[4+ln:]
	}
	return tags, vals
}

func find(tag uint16, tags []uint16, vals [][]byte) []byte {
	for i, g := range tags {
		if g == tag {
			return vals[i]
		}
	}
	return nil
}

func camReply(t *testing.T) []byte {
	t.Helper()
	h := handler(t)
	form := url.Values{"version": {"25"}, "username": {"leia@example.org"}, "password": {"pw1"}, "consoleId": {"00"}}.Encode()
	w := post(h, "/native/cam/authenticate.action", form)
	if w.Code != 200 {
		t.Fatalf("authenticate.action status = %d", w.Code)
	}
	b := w.Body.Bytes()
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		t.Fatalf("reply prefix = % x, want success", b[:4])
	}
	return b[4:]
}

// The 0x5e account struct: FUN_000dd9ac needs >= 0x3c bytes, fixed fields at
// +0x00 (u64 id), +0x08 (17-byte online ID), +0x19 (3-byte country),
// +0x1c (language), and a NONZERO-length 0x5d credential at +0x38.
func TestCAMReplyAccount(t *testing.T) {
	tags, vals := elems(t, camReply(t))
	a := find(0x5e, tags, vals)
	if a == nil {
		t.Fatal("missing 0x5e account element")
	}
	if len(a) < 0x3c {
		t.Fatalf("0x5e length %d < 0x3c", len(a))
	}
	if binary.BigEndian.Uint64(a[0:8]) == 0 {
		t.Error("0x5e +0x00 account id is zero")
	}
	if got := string(a[8:8+4]); got != "Leia" {
		t.Errorf("0x5e +0x08 online ID = %q, want Leia*", got)
	}
	if got := string(a[0x19:0x1b]); got != "se" {
		t.Errorf("0x5e +0x19 country = %q, want lower-case se", got)
	}
	if got := string(a[0x1c:0x1e]); got != "en" {
		t.Errorf("0x5e +0x1c language = %q, want en", got)
	}
	stags, svals := elems(t, a[0x38:])
	c := find(0x5d, stags, svals)
	if c == nil || len(c) == 0 {
		t.Error("0x5d credential inside 0x5e missing or zero-length (loader rejects it)")
	}
}

// Element minimum lengths (0x5e/0x5f >= 0x3c, entry >= 0x2a, 0x5d nonzero,
// empty 0x15 list, 0x7d/0x7e present) are pinned by validateCAMLoader in
// handlers_test.go; the field offsets below are the part it doesn't check.
