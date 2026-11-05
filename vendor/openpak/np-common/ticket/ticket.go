// Package ticket implements the firmware-4.93 NP ticket envelope. The final
// extension is authenticated by an owner-local Ed25519 key; it is an OpenPak
// extension, not a Sony signature. See docs/provenance.md.
package ticket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"openpak/np-common/onlineid"
)

var ErrInvalid = errors.New("invalid or expired NP ticket")

const MaxSize = 0x800
const envelopeSize = 272

var magic = []byte("OPKT1")

type Identity struct {
	AccountID string `json:"account"`
	LinkID    string `json:"link"`
	OnlineID  string `json:"online"`
	Country   string `json:"country"`
	Birthday  string `json:"birthday,omitempty"` // core accounts.birthday, ISO 8601 date; empty when the core has none
	Service   string `json:"service"`
	ConsoleID string `json:"console"`
	Issued    int64  `json:"iat"`
	Expires   int64  `json:"exp"`
	// Cookie is the 24 bytes a game passes in its ticket request. It is not part of the signed claims
	// but is written to the end of the ticket body, which the signature covers, so a game server such as
	// Demonware can use it as the key of its auth reply. Empty when the request carried none.
	Cookie []byte `json:"-"`
}

// CookieSize is the length of the game's request cookie.
const CookieSize = 24

type Signer struct {
	key ed25519.PrivateKey
	now func() time.Time
}

func New(key ed25519.PrivateKey, now func() time.Time) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("NP ticket key must be Ed25519")
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{append(ed25519.PrivateKey(nil), key...), now}, nil
}
func Load(path string) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("ticket key must be PKCS8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("ticket key must be Ed25519")
	}
	return New(ed, nil)
}
func elem(tag uint16, value []byte) []byte {
	n := 4
	if tag == 0x3000 || tag == 0x3010 {
		n = 6
	}
	b := make([]byte, n+len(value))
	binary.BigEndian.PutUint16(b, tag)
	if n == 6 {
		binary.BigEndian.PutUint32(b[2:], uint32(len(value)))
	} else {
		binary.BigEndian.PutUint16(b[2:], uint16(len(value)))
	}
	copy(b[n:], value)
	return b
}

// languageEnglishUS is the CELL_SYSUTIL_LANG id written in the region field's last byte. The core
// stores no language; firmware 4.93 copies this byte into its language setting (id 0 would be
// Japanese), so OpenPak uses the same English default as the native bindAccount reply.
const languageEnglishUS = 1

// birthFields derives the two ticket values built from the core's birthday. Table 0x684558 index
// 0xb (tag 0x3011, 4 bytes) is the date of birth as year u16, month, day: vsh FUN_001bbc10 passes
// it as the last-but-one stack argument of FUN_001bb88c and writes year<<16|month<<8|day to
// xRegistry /setting/user/N/npguest/birth (id 0x84), which regcam's country/language/date-of-birth
// form (FUN_00067724) reads; zero makes What's New / Account Information ask for it. Index 9 (the
// status word) carries the age in the low 7 bits of byte 0 (FUN_001bb88c stores it as ctx+0x274).
// Both stay zero when the core holds no valid birthday.
func birthFields(birthday string, now time.Time) (dob []byte, status []byte) {
	dob, status = make([]byte, 4), make([]byte, 4)
	b, err := time.Parse("2006-01-02", birthday)
	if err != nil || b.After(now) {
		return
	}
	age := now.Year() - b.Year()
	if now.Month() < b.Month() || (now.Month() == b.Month() && now.Day() < b.Day()) {
		age--
	}
	if age > 0x7f {
		age = 0x7f
	}
	status[0] = byte(age)
	binary.BigEndian.PutUint16(dob, uint16(b.Year()))
	dob[2], dob[3] = byte(b.Month()), byte(b.Day())
	return
}
func fixed(s string, n int) []byte { b := make([]byte, n); copy(b, s); return b }
func u64(v uint64) []byte          { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func (s *Signer) Issue(id Identity, ttl time.Duration) ([]byte, error) {
	if !onlineid.Valid(id.OnlineID) || len(id.Country) != 2 || len(id.Service) > 24 || id.AccountID == "" || id.LinkID == "" || ttl < time.Minute || ttl > 24*time.Hour {
		return nil, ErrInvalid
	}
	id.Issued = s.now().UnixMilli()
	id.Expires = s.now().Add(ttl).UnixMilli()
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	region := fixed(id.Country, 4)
	region[3] = languageEnglishUS
	dob, status := birthFields(id.Birthday, s.now())
	if len(id.Cookie) != 0 && len(id.Cookie) != CookieSize {
		return nil, ErrInvalid
	}
	values := [][]byte{nonce, make([]byte, 4), u64(uint64(id.Issued)), u64(uint64(id.Expires)), u64(onlineid.AccountID(id.AccountID)), fixed(id.OnlineID, 32), region, fixed("un", 4), fixed(id.Service, 24), dob, status, make([]byte, 8)}
	tags := []uint16{8, 1, 7, 7, 2, 4, 8, 4, 8, 0x3011, 1, 7}
	var body []byte
	for i, v := range values {
		body = append(body, elem(tags[i], v)...)
	}
	if len(id.Cookie) == CookieSize { // after the firmware's own fields, so their order is untouched
		body = append(body, elem(8, id.Cookie)...)
	}
	out := append([]byte{0x40, 0, 0, 0}, elem(0x3000, body)...)
	out = append(out, elem(0x3010, nil)...)
	out = append(out, elem(8, make([]byte, 8))...)
	out = append(out, elem(8, make([]byte, 64))...)
	claims, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	payload := append(append([]byte{}, magic...), claims...)
	signed := append(append([]byte("openpak-np-ticket-v1\x00"), out...), payload...)
	payload = append(payload, ed25519.Sign(s.key, signed)...)
	out = append(out, elem(0x3012, payload)...)
	if len(out) > MaxSize {
		return nil, ErrInvalid
	}
	return out, nil
}

// envelope measures the signed part of a ticket: [40 00 00 00], the 0x3000 body, 0x3010 and two
// blocks of tag 8, up to the 0x3012 OpenPak extension. It returns the offset of that extension and
// the body (the fields), or ok false.
func envelope(raw []byte) (end int, body []byte, ok bool) {
	if len(raw) < 4 || !bytes.Equal(raw[:4], []byte{0x40, 0, 0, 0}) {
		return 0, nil, false
	}
	p := 4
	for i := 0; ; i++ {
		if p+4 > len(raw) {
			return 0, nil, false
		}
		tag := binary.BigEndian.Uint16(raw[p:])
		if tag == 0x3012 {
			return p, body, i >= 1
		}
		hdr, n := 4, int(binary.BigEndian.Uint16(raw[p+2:]))
		if tag == 0x3000 || tag == 0x3010 {
			if p+6 > len(raw) {
				return 0, nil, false
			}
			hdr, n = 6, int(binary.BigEndian.Uint32(raw[p+2:]))
		}
		if n < 0 || p+hdr+n > len(raw) || i > 8 {
			return 0, nil, false
		}
		if tag == 0x3000 {
			body = raw[p+hdr : p+hdr+n]
		}
		p += hdr + n
	}
}

// Verify authenticates the exact issued envelope and claims. Firmware may append
// device extensions; callers never interpret those as authentication claims. The
// body may carry the game's request cookie after the firmware fields.
func (s *Signer) Verify(raw []byte) (Identity, error) {
	var id Identity
	end, body, ok := envelope(raw)
	if !ok || len(raw) > 8192 || end > envelopeSize+64 {
		return id, ErrInvalid
	}
	n := int(binary.BigEndian.Uint16(raw[end+2:]))
	last := end + 4 + n
	if last > len(raw) || last > MaxSize || n < len(magic)+ed25519.SignatureSize {
		return id, ErrInvalid
	}
	payload := raw[end+4 : last-ed25519.SignatureSize]
	sig := raw[last-ed25519.SignatureSize : last]
	if !bytes.HasPrefix(payload, magic) {
		return id, ErrInvalid
	}
	signed := append(append([]byte("openpak-np-ticket-v1\x00"), raw[:end]...), payload...)
	if !ed25519.Verify(s.key.Public().(ed25519.PublicKey), signed, sig) || json.Unmarshal(payload[len(magic):], &id) != nil {
		return Identity{}, ErrInvalid
	}
	now := s.now().UnixMilli()
	if id.Expires <= now || id.Issued > now+30000 || id.Expires <= id.Issued || id.Expires-id.Issued > int64(24*time.Hour/time.Millisecond) || id.AccountID == "" || id.LinkID == "" || !onlineid.Valid(id.OnlineID) {
		return Identity{}, ErrInvalid
	}
	// Fields 0..11 are the firmware's; a 13th, 24-byte field is the cookie.
	p, idx := 0, 0
	for p+4 <= len(body) {
		l := int(binary.BigEndian.Uint16(body[p+2:]))
		if p+4+l > len(body) {
			break
		}
		if idx == 12 && l == CookieSize {
			id.Cookie = append([]byte(nil), body[p+4:p+4+l]...)
		}
		p += 4 + l
		idx++
	}
	return id, nil
}

// Fingerprint identifies the signing public key without exposing private material.
func (s *Signer) Fingerprint() [32]byte { return sha256.Sum256(s.key.Public().(ed25519.PublicKey)) }
