// Package native serves the PS3 firmware's "native" registration web service
// (POST /native/reg/<name>.action): replies are big-endian binary TLV, not XML or JSON.
// Layout from the firmware (docs/ps3/psn-signin-findings.md): a 4-byte prefix (byte 1 = result,
// 0 = OK), then elements of u16 tag | u16 length | value. A list is a tag-1 element whose value
// starts u16 id | u16 count, followed by count child elements tagged id.
package native

import "encoding/binary"

// Elem encodes one element.
func Elem(tag uint16, val []byte) []byte {
	b := make([]byte, 4, 4+len(val))
	binary.BigEndian.PutUint16(b, tag)
	binary.BigEndian.PutUint16(b[2:], uint16(len(val)))
	return append(b, val...)
}

// List encodes a tag-1 list element holding items already encoded as elements tagged id.
func List(id uint16, items ...[]byte) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint16(v, id)
	binary.BigEndian.PutUint16(v[2:], uint16(len(items)))
	for _, it := range items {
		v = append(v, it...)
	}
	return Elem(1, v)
}

// Reply is a successful reply: prefix 00 00 00 00 plus the given elements.
func Reply(elems ...[]byte) []byte {
	b := []byte{0, 0, 0, 0}
	for _, e := range elems {
		b = append(b, e...)
	}
	return b
}

// ErrorReply is an application error: HTTP 200 with a non-zero result byte, which the firmware
// shows as 0x80023100|code.
func ErrorReply(code byte) []byte { return []byte{0, code, 0, 0} }

// fixed returns s NUL-padded (or cut) to n bytes.
func fixed(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}
