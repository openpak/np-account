package coreclient_test

import (
	"context"
	"errors"
	"testing"

	accountv1 "openpak/np-account/internal/accountpb"
	"openpak/np-account/internal/coreclient"
	"openpak/np-account/internal/fakecore"
)

const coreKey = "fake-core-key-fake-core-key-fake-core-key"

func setup(t *testing.T) (*coreclient.Client, *fakecore.Core) {
	t.Helper()
	core := fakecore.New(coreKey)
	core.AddAccount(fakecore.Account{ID: "acc-1", Email: "leia@example.org", Password: "pw1", DisplayName: "Leia", Country: "SE"})
	core.AddAccount(fakecore.Account{ID: "acc-2", Email: "han@example.org", Password: "pw2", DisplayName: "Han", Country: "US", TOTP: "123456"})
	core.AddAccount(fakecore.Account{ID: "acc-3", Email: "ban@example.org", Password: "pw3", DisplayName: "Ban", Status: accountv1.AccountStatus_ACCOUNT_STATUS_BANNED})
	cli, err := coreclient.Dial("passthrough:///core", coreKey, core.Serve(t)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli, core
}

func TestVerifyPassword(t *testing.T) {
	cli, _ := setup(t)
	for _, tc := range []struct {
		name, email, pw string
		want            error
		account         string
		twoFactor       bool
	}{
		{"ok", "leia@example.org", "pw1", nil, "acc-1", false},
		{"two factor owed", "han@example.org", "pw2", nil, "acc-2", true},
		{"wrong password", "leia@example.org", "nope", coreclient.ErrInvalidCredentials, "", false},
		{"unknown email", "who@example.org", "pw1", coreclient.ErrInvalidCredentials, "", false},
		{"banned", "ban@example.org", "pw3", coreclient.ErrAccountDisabled, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := cli.VerifyPassword(context.Background(), tc.email, tc.pw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err == nil && (v.AccountID != tc.account || v.TwoFactorRequired != tc.twoFactor) {
				t.Fatalf("got %+v", v)
			}
		})
	}
}

func TestVerifySecondFactor(t *testing.T) {
	cli, _ := setup(t)
	ctx := context.Background()
	if err := cli.VerifySecondFactor(ctx, "acc-2", "123456", ""); err != nil {
		t.Fatalf("good code: %v", err)
	}
	if err := cli.VerifySecondFactor(ctx, "acc-2", "000000", ""); !errors.Is(err, coreclient.ErrInvalidSecondFactor) {
		t.Fatalf("bad code: %v", err)
	}
	if err := cli.VerifySecondFactor(ctx, "acc-1", "123456", ""); !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("no second factor on account: %v", err)
	}
}

func TestClaimAndLookup(t *testing.T) {
	cli, core := setup(t)
	ctx := context.Background()

	if _, err := cli.GetLinkByAccount(ctx, "acc-1"); !errors.Is(err, coreclient.ErrNoLink) {
		t.Fatalf("before claim: %v", err)
	}
	l, err := cli.ClaimOnlineID(ctx, "acc-1", "Leia_B")
	if err != nil || l.OnlineID != "Leia_B" || l.AccountID != "acc-1" {
		t.Fatalf("claim: %+v %v", l, err)
	}
	for _, call := range []string{"Links.ReserveLink", "Links.ActivateLink", "Links.SetLinkPublicCode"} {
		if core.Called(call) != 1 {
			t.Errorf("%s calls = %d", call, core.Called(call))
		}
	}
	byAcc, err := cli.GetLinkByAccount(ctx, "acc-1")
	if err != nil || byAcc.OnlineID != "Leia_B" || byAcc.LinkID != l.LinkID {
		t.Fatalf("by account: %+v %v", byAcc, err)
	}
	bySub, err := cli.GetLinkByOnlineID(ctx, "Leia_B")
	if err != nil || bySub.AccountID != "acc-1" {
		t.Fatalf("by subject: %+v %v", bySub, err)
	}

	// Same subject, other account: refused at reserve.
	if _, err := cli.ClaimOnlineID(ctx, "acc-2", "Leia_B"); !errors.Is(err, coreclient.ErrOnlineIDTaken) {
		t.Fatalf("exact duplicate: %v", err)
	}
	// Case/punctuation variant: refused at the public code, and the link is revoked again.
	if _, err := cli.ClaimOnlineID(ctx, "acc-2", "leiab"); !errors.Is(err, coreclient.ErrOnlineIDTaken) {
		t.Fatalf("variant: %v", err)
	}
	if _, err := cli.GetLinkByAccount(ctx, "acc-2"); !errors.Is(err, coreclient.ErrNoLink) {
		t.Fatalf("variant must not leave a link: %v", err)
	}
	if _, err := cli.GetLinkByOnlineID(ctx, "nobody"); !errors.Is(err, coreclient.ErrNoLink) {
		t.Fatalf("unknown subject: %v", err)
	}
}

func TestGetAccount(t *testing.T) {
	cli, _ := setup(t)
	ctx := context.Background()
	a, err := cli.GetAccount(ctx, "acc-1")
	if err != nil || a.DisplayName != "Leia" || a.Country != "SE" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := cli.GetAccount(ctx, "acc-3"); !errors.Is(err, coreclient.ErrAccountDisabled) {
		t.Fatalf("banned: %v", err)
	}
	if _, err := cli.GetAccount(ctx, "zzz"); !errors.Is(err, coreclient.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestFailsClosed(t *testing.T) {
	cli, core := setup(t)
	ctx := context.Background()
	core.Down = true
	if _, err := cli.VerifyPassword(ctx, "leia@example.org", "pw1"); !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("core down: %v", err)
	}
	if _, err := cli.GetLinkByAccount(ctx, "acc-1"); !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("core down link: %v", err)
	}
	core.Down = false

	bad, err := coreclient.Dial("passthrough:///core", "wrong-key", core.Serve(t)...)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	// The core answers a bad key with Unauthenticated, which looks like bad
	// credentials on the wire; either way nothing verifies.
	if _, err := bad.VerifyPassword(ctx, "leia@example.org", "pw1"); err == nil {
		t.Fatal("a wrong internal key must not verify anything")
	}
}
