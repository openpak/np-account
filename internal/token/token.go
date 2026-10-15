// Package token issues and verifies the short-lived tokens np-account hands
// out: grant codes, access tokens, the npsso session, console tokens, and the
// id_token. They are HMAC-SHA256 signed with keys derived per purpose from
// NP_TOKEN_KEY, so a token of one kind never verifies as another. Nothing is
// stored: verification needs only the key and the clock.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Kinds of token.
const (
	KindGrant   = "grant"   // authorization grant code, single use
	KindAccess  = "access"  // OAuth access token
	KindNPSSO   = "npsso"   // npsso_token cookie: console sign-in session
	KindConsole = "console" // console token from lwConsoleToken
)

var (
	ErrInvalid = errors.New("token invalid")
	ErrExpired = errors.New("token expired")
)

// Claims is the payload of every token kind. Fields a kind does not use are
// empty.
type Claims struct {
	Kind      string `json:"k"`
	Expires   int64  `json:"exp"`
	JTI       string `json:"jti"`
	AccountID string `json:"aid,omitempty"`
	LinkID    string `json:"lid,omitempty"`
	OnlineID  string `json:"oid,omitempty"`
}

type Signer struct {
	key []byte
	now func() time.Time
}

// New returns a Signer. now may be nil (time.Now).
func New(key string, now func() time.Time) *Signer {
	if now == nil {
		now = time.Now
	}
	return &Signer{key: []byte(key), now: now}
}

func (s *Signer) subkey(purpose string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("np-account/" + purpose))
	return m.Sum(nil)
}

func (s *Signer) mac(purpose, data string) string {
	m := hmac.New(sha256.New, s.subkey(purpose))
	m.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Cred derives the 32-byte NP credential blob handed to the console at sign-in (the firmware stores it
// opaquely and sends it back when it asks for tickets): HMAC-SHA256 over the link, stable for the link's life.
func (s *Signer) Cred(linkID, onlineID string) []byte {
	m := hmac.New(sha256.New, s.subkey("np-cred"))
	m.Write([]byte(linkID + "\x00" + onlineID))
	return m.Sum(nil)
}

// Issue signs c as a token of kind valid for ttl. Kind, expiry and a random
// JTI are filled in.
func (s *Signer) Issue(kind string, c Claims, ttl time.Duration) string {
	c.Kind = kind
	c.Expires = s.now().Add(ttl).Unix()
	c.JTI = randomID()
	raw, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + s.mac(kind, body)
}

// Verify checks signature, kind and expiry.
func (s *Signer) Verify(kind, tok string) (Claims, error) {
	var c Claims
	body, sig, ok := strings.Cut(tok, ".")
	if !ok || body == "" || !hmac.Equal([]byte(sig), []byte(s.mac(kind, body))) {
		return c, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Kind != kind {
		return Claims{}, ErrInvalid
	}
	if s.now().Unix() >= c.Expires {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// IDToken signs claims as a compact JWT (HS256, header {"alg":"HS256","typ":"JWT"}).
// Whether the firmware parses id_token as a JWT is UNCONFIRMED; the claim names
// are the ones the firmware module reads.
func (s *Signer) IDToken(claims map[string]any) (string, error) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := hdr + "." + base64.RawURLEncoding.EncodeToString(raw)
	return signing + "." + s.mac("id_token", signing), nil
}

// VerifyIDToken checks an id_token and returns its claims.
func (s *Signer) VerifyIDToken(tok string) (map[string]any, error) {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 || !hmac.Equal([]byte(tok[i+1:]), []byte(s.mac("id_token", tok[:i]))) {
		return nil, ErrInvalid
	}
	parts := strings.Split(tok[:i], ".")
	if len(parts) != 2 {
		return nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil, ErrInvalid
	}
	return m, nil
}

func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("token: no entropy: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
