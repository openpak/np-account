package events

import (
	"context"
	"errors"
	"testing"

	"openpak/np-account/internal/coreclient"
)

func ev(v uint64, typ, acct string) coreclient.Event {
	return coreclient.Event{Version: v, ID: "e" + typ, Type: typ, AccountID: acct}
}

func TestPlan(t *testing.T) {
	for typ, want := range map[string]Action{
		"account_banned": Ban, "account_unbanned": Unban, "account_delete_started": Suspend,
		"account_restored": Restore, "account_deleted": Purge, "friend_requested": None, "link_unlinked": None,
	} {
		if got := Plan(ev(1, typ, "a")); got != want {
			t.Errorf("%s: %v, want %v", typ, got, want)
		}
	}
	if Plan(ev(1, "account_banned", "")) != None {
		t.Fatal("an event without an account must do nothing")
	}
}

func TestSuspendRestorePurgeAndRedelivery(t *testing.T) {
	s := NewState()
	if s.Apply(ev(1, "account_delete_started", "a")) != Suspend || !s.Denied("a") {
		t.Fatal("delete_started must deny")
	}
	if s.Apply(ev(1, "account_delete_started", "a")) != None {
		t.Fatal("a redelivered version must be a no-op")
	}
	s.Apply(ev(2, "account_banned", "a"))
	s.Apply(ev(3, "account_restored", "a"))
	if !s.Denied("a") {
		t.Fatal("restoring a closed account must not lift a ban")
	}
	s.Apply(ev(4, "account_unbanned", "a"))
	if s.Denied("a") {
		t.Fatal("unbanned and restored: admitted again")
	}
	s.Apply(ev(5, "account_delete_started", "a"))
	if s.Apply(ev(6, "account_deleted", "a")) != Purge || s.Denied("a") || len(s.acct) != 0 {
		t.Fatal("purge must drop everything held for the account")
	}
	if s.Apply(ev(3, "account_banned", "a")) != None || s.Denied("a") {
		t.Fatal("an old version must not be applied")
	}
	if s.Cursor() != 6 {
		t.Fatalf("cursor %d", s.Cursor())
	}
}

type fakePoll struct {
	evs   []coreclient.Event
	since []uint64
}

func (f *fakePoll) PollEvents(_ context.Context, since uint64, _ int) ([]coreclient.Event, error) {
	f.since = append(f.since, since)
	var out []coreclient.Event
	for _, e := range f.evs {
		if e.Version > since {
			out = append(out, e)
		}
	}
	return out, nil
}

func TestConsumerCutsDeniedAndPurgedAccounts(t *testing.T) {
	p := &fakePoll{evs: []coreclient.Event{
		ev(1, "account_delete_started", "a"), ev(2, "friend_requested", "b"),
		ev(3, "account_restored", "a"), ev(4, "account_banned", "b"), ev(5, "account_deleted", "c"),
	}}
	var cut []string
	c := &Consumer{Core: p, State: NewState(), Cut: func(a string) int { cut = append(cut, a); return 1 }}
	if n, err := c.ProcessOnce(context.Background()); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	if len(cut) != 3 || cut[0] != "a" || cut[1] != "b" || cut[2] != "c" {
		t.Fatalf("cut %v", cut)
	}
	// The same page again (a retry): the cursor skips it, nothing is cut twice.
	if n, _ := c.ProcessOnce(context.Background()); n != 0 || len(cut) != 3 || p.since[1] != 5 {
		t.Fatalf("redelivery: n=%d cut=%v since=%v", n, cut, p.since)
	}
	if c.State.Denied("a") || !c.State.Denied("b") {
		t.Fatal("a restored, b banned")
	}
}

func TestGateRefusesDeniedAccountsWithoutAskingTheCore(t *testing.T) {
	s := NewState()
	s.Apply(ev(1, "account_banned", "a"))
	g := Gate{State: s} // nil client: asking the core would panic
	if _, err := g.GetAccount(context.Background(), "a"); !errors.Is(err, coreclient.ErrAccountDisabled) {
		t.Fatal(err)
	}
}
