// Package oauth is the PS3 sign-in surface: /2.0/oauth/authorize,
// /2.0/oauth/token and the console token. It owns no identity; every check
// goes to the account core through the Core interface.
package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/coreclient"
	"openpak/np-account/internal/onlineid"
	"openpak/np-account/internal/token"
)

// Lifetimes of the tokens issued here.
const (
	GrantTTL   = 5 * time.Minute
	NPSSOTTL   = time.Hour
	ConsoleTTL = 24 * time.Hour

	defaultCountry = "us"
)

// Core is what the service needs from the account core; *coreclient.Client
// implements it.
type Core interface {
	VerifyPassword(ctx context.Context, email, password string) (*coreclient.Verified, error)
	VerifySecondFactor(ctx context.Context, accountID, code, recoveryCode string) error
	GetAccount(ctx context.Context, accountID string) (*coreclient.Account, error)
	GetLinkByAccount(ctx context.Context, accountID string) (*coreclient.Link, error)
	GetLinkByOnlineID(ctx context.Context, onlineID string) (*coreclient.Link, error)
	ClaimOnlineID(ctx context.Context, accountID, onlineID string) (*coreclient.Link, error)
}

type Service struct {
	cfg    *config.Config
	core   Core
	signer *token.Signer
	now    func() time.Time
	log    *slog.Logger

	mu   sync.Mutex
	used map[string]int64 // grant-code JTI -> expiry (unix), single use
}

// New returns a Service. now and log may be nil.
func New(cfg *config.Config, core Core, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{cfg: cfg, core: core, signer: token.New(cfg.TokenKey, now), now: now, log: log, used: map[string]int64{}}
}

// Signer exposes the token signer (for the server's console token and tests).
func (s *Service) Signer() *token.Signer { return s.signer }

// Tokens is the result of a successful sign-in or code exchange.
type Tokens struct {
	AccessToken string
	ExpiresIn   int
	IDToken     string
	Scope       string
	GrantCode   string // password grant only
	NPSSO       string // password grant only
}

// PasswordInput is the form of grant_type=password.
type PasswordInput struct {
	ClientID, ClientSecret string
	Username, Password     string
	Scope                  string
	SecondFactor           string // OpenPak extension, see README
	RecoveryCode           string // OpenPak extension, see README
	OnlineID               string // OpenPak extension, see README
}

func (s *Service) checkClient(id, secret string) *Error {
	okID := subtle.ConstantTimeCompare([]byte(id), []byte(s.cfg.ClientID))
	okSecret := subtle.ConstantTimeCompare([]byte(secret), []byte(s.cfg.ClientSecret))
	if okID&okSecret != 1 {
		return errInvalidClient()
	}
	return nil
}

// CheckClientID is the authorize-side check: only the id is sent there.
func (s *Service) CheckClientID(id string) *Error {
	if subtle.ConstantTimeCompare([]byte(id), []byte(s.cfg.ClientID)) != 1 {
		return errInvalidClient()
	}
	return nil
}

// coreErr maps a core-client error to an OAuth error, failing closed.
func (s *Service) coreErr(err error) *Error {
	switch {
	case errors.Is(err, coreclient.ErrInvalidCredentials):
		return errBadCredentials()
	case errors.Is(err, coreclient.ErrAccountDisabled):
		return errDisabled()
	case errors.Is(err, coreclient.ErrInvalidSecondFactor):
		return errBadSecondFactor()
	case errors.Is(err, coreclient.ErrRateLimited):
		return errRateLimited()
	case errors.Is(err, coreclient.ErrOnlineIDTaken):
		return errOnlineIDTaken()
	case errors.Is(err, coreclient.ErrNoLink), errors.Is(err, coreclient.ErrNotFound):
		return errBadGrant()
	case errors.Is(err, coreclient.ErrUnavailable):
		s.log.Error("account core unavailable")
		return errServer(503)
	}
	s.log.Error("unexpected core error", "err", err)
	return errServer(500)
}

// PasswordGrant signs a console in with an email and password.
func (s *Service) PasswordGrant(ctx context.Context, in PasswordInput) (*Tokens, *Error) {
	if e := s.checkClient(in.ClientID, in.ClientSecret); e != nil {
		return nil, e
	}
	if in.Username == "" || in.Password == "" {
		return nil, errInvalidRequest("username and password are required")
	}
	v, err := s.core.VerifyPassword(ctx, in.Username, in.Password)
	if err != nil {
		return nil, s.coreErr(err)
	}
	if v.TwoFactorRequired {
		if in.SecondFactor == "" && in.RecoveryCode == "" {
			return nil, errSecondFactor()
		}
		if err := s.core.VerifySecondFactor(ctx, v.AccountID, in.SecondFactor, in.RecoveryCode); err != nil {
			return nil, s.coreErr(err)
		}
	}
	acct, err := s.core.GetAccount(ctx, v.AccountID)
	if err != nil {
		return nil, s.coreErr(err)
	}
	link, e := s.resolveLink(ctx, acct, in.OnlineID)
	if e != nil {
		return nil, e
	}
	t, e := s.issue(link, acct, in.Scope)
	if e != nil {
		return nil, e
	}
	c := token.Claims{AccountID: link.AccountID, LinkID: link.LinkID, OnlineID: link.OnlineID}
	t.GrantCode = s.signer.Issue(token.KindGrant, c, GrantTTL)
	t.NPSSO = s.signer.Issue(token.KindNPSSO, c, NPSSOTTL)
	s.log.Info("np sign-in", "online_id", link.OnlineID)
	return t, nil
}

// resolveLink returns the account's np link, creating it on first sign-in
// from the supplied online ID or, when enabled, from the display name.
func (s *Service) resolveLink(ctx context.Context, acct *coreclient.Account, wanted string) (*coreclient.Link, *Error) {
	link, err := s.core.GetLinkByAccount(ctx, acct.ID)
	if err == nil {
		return link, nil
	}
	if !errors.Is(err, coreclient.ErrNoLink) {
		return nil, s.coreErr(err)
	}
	id := wanted
	switch {
	case id != "":
		if !onlineid.Valid(id) {
			return nil, errInvalidOnlineID()
		}
	case s.cfg.AutoOnlineID:
		var ok bool
		if id, ok = onlineid.FromDisplayName(acct.DisplayName); !ok {
			return nil, errOnlineIDRequired()
		}
	default:
		return nil, errOnlineIDRequired()
	}
	link, err = s.core.ClaimOnlineID(ctx, acct.ID, id)
	if err != nil {
		return nil, s.coreErr(err)
	}
	return link, nil
}

// CodeInput is the form of the grant-code exchange.
type CodeInput struct {
	ClientID, ClientSecret string
	Code                   string
	Scope                  string
}

// CodeGrant exchanges a grant code, once, for tokens. The account and link
// are re-read from the core, so a ban after the code was issued is honoured.
func (s *Service) CodeGrant(ctx context.Context, in CodeInput) (*Tokens, *Error) {
	if e := s.checkClient(in.ClientID, in.ClientSecret); e != nil {
		return nil, e
	}
	if in.Code == "" {
		return nil, errInvalidRequest("code is required")
	}
	c, err := s.signer.Verify(token.KindGrant, in.Code)
	if err != nil || !s.consume(c) {
		return nil, errBadGrant()
	}
	t, e := s.fresh(ctx, c, in.Scope)
	if e != nil {
		return nil, e
	}
	return t, nil
}

// Authorize turns a valid npsso session into a new single-use grant code.
func (s *Service) Authorize(ctx context.Context, clientID, npsso string) (string, *Error) {
	if e := s.CheckClientID(clientID); e != nil {
		return "", e
	}
	c, err := s.signer.Verify(token.KindNPSSO, npsso)
	if err != nil {
		return "", errLoginRequired()
	}
	// Re-check the account and link so a banned or unlinked session is dead.
	if _, e := s.fresh(ctx, c, ""); e != nil {
		return "", e
	}
	return s.signer.Issue(token.KindGrant, token.Claims{AccountID: c.AccountID, LinkID: c.LinkID, OnlineID: c.OnlineID}, GrantTTL), nil
}

// fresh re-reads account and link for a token's claims and issues tokens.
func (s *Service) fresh(ctx context.Context, c token.Claims, scope string) (*Tokens, *Error) {
	acct, err := s.core.GetAccount(ctx, c.AccountID)
	if err != nil {
		return nil, s.coreErr(err)
	}
	link, err := s.core.GetLinkByOnlineID(ctx, c.OnlineID)
	if err != nil {
		return nil, s.coreErr(err)
	}
	if link.AccountID != acct.ID || link.LinkID != c.LinkID {
		return nil, errBadGrant()
	}
	return s.issue(link, acct, scope)
}

// consume marks a grant code used; false if it already was.
func (s *Service) consume(c token.Claims) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	for jti, exp := range s.used {
		if exp <= now {
			delete(s.used, jti)
		}
	}
	if _, dup := s.used[c.JTI]; dup {
		return false
	}
	s.used[c.JTI] = c.Expires
	return true
}

func (s *Service) issue(link *coreclient.Link, acct *coreclient.Account, scope string) (*Tokens, *Error) {
	now := s.now()
	ttl := s.cfg.AccessTTL
	country := strings.ToLower(acct.Country)
	if country == "" {
		country = defaultCountry
	}
	idt, err := s.signer.IDToken(map[string]any{
		"iss":         "openpak-np-account",
		"aud":         s.cfg.ClientID,
		"iat":         now.Unix(),
		"exp":         now.Add(ttl).Unix(),
		"auth_time":   now.Unix(),
		"env_iss_id":  s.cfg.EnvIssID,
		"user_id":     onlineid.UserID(link.LinkID),
		"acct_id":     link.AccountID,
		"ctry_code":   country,
		"comm_domain": s.cfg.CommDomain,
		"online_id":   link.OnlineID,
	})
	if err != nil {
		return nil, errServer(500)
	}
	if scope = strings.TrimSpace(scope); scope == "" || len(scope) > 256 {
		scope = "openid"
	}
	return &Tokens{
		AccessToken: s.signer.Issue(token.KindAccess, token.Claims{AccountID: link.AccountID, LinkID: link.LinkID, OnlineID: link.OnlineID}, ttl),
		ExpiresIn:   int(ttl / time.Second),
		IDToken:     idt,
		Scope:       scope,
	}, nil
}

// ConsoleToken issues a console token (the lwConsoleToken reply).
func (s *Service) ConsoleToken() string {
	return s.signer.Issue(token.KindConsole, token.Claims{}, ConsoleTTL)
}

// CheckConsoleToken validates the X-NP-CONSOLE-TOKEN header value. An empty
// value passes unless the config requires one.
func (s *Service) CheckConsoleToken(v string) *Error {
	if v == "" {
		if s.cfg.RequireConsoleToken {
			return errConsoleToken()
		}
		return nil
	}
	if _, err := s.signer.Verify(token.KindConsole, v); err != nil {
		return errConsoleToken()
	}
	return nil
}

// NativeIdentity is the result of a native-API sign-in (POST /native/reg/bindAccount.action).
type NativeIdentity struct {
	AccountID  string // core account id
	LinkID     string
	OnlineID   string
	Country    string // lower-case ISO code, "us" when unknown
	Credential []byte // 32-byte NP credential blob
}

// NativeSignIn checks an email and password and returns the account's np identity, creating the link
// on first sign-in when NP_AUTO_ONLINE_ID is set. Accounts with a second factor cannot sign in here:
// the native form has no field for it.
func (s *Service) NativeSignIn(ctx context.Context, username, password string) (*NativeIdentity, *Error) {
	if username == "" || password == "" {
		return nil, errBadCredentials()
	}
	v, err := s.core.VerifyPassword(ctx, username, password)
	if err != nil {
		return nil, s.coreErr(err)
	}
	if v.TwoFactorRequired {
		return nil, errSecondFactor()
	}
	acct, err := s.core.GetAccount(ctx, v.AccountID)
	if err != nil {
		return nil, s.coreErr(err)
	}
	link, e := s.resolveLink(ctx, acct, "")
	if e != nil {
		return nil, e
	}
	country := strings.ToLower(acct.Country)
	if country == "" {
		country = defaultCountry
	}
	s.log.Info("np native sign-in", "online_id", link.OnlineID)
	return &NativeIdentity{AccountID: link.AccountID, LinkID: link.LinkID, OnlineID: link.OnlineID, Country: country, Credential: s.signer.Cred(link.LinkID, link.OnlineID)}, nil
}
