package oauth

import (
	"context"
	"errors"
	"openpak/np-account/internal/coreclient"
	"testing"
)

type handleProvisionCore struct {
	calls []string
	taken bool
}

func (f *handleProvisionCore) GetLinkByAccount(context.Context, string) (*coreclient.Link, error) {
	return nil, coreclient.ErrNoLink
}
func (f *handleProvisionCore) ClaimOnlineID(_ context.Context, account, name string) (*coreclient.Link, error) {
	f.calls = append(f.calls, name)
	if f.taken {
		return nil, coreclient.ErrOnlineIDTaken
	}
	return &coreclient.Link{AccountID: account, OnlineID: name, LinkID: "stable-link"}, nil
}
func TestProvisionUsesHandleVerbatim(t *testing.T) {
	for _, taken := range []bool{false, true} {
		f := &handleProvisionCore{taken: taken}
		link, err := EnsureNPLink(context.Background(), f, &coreclient.Account{ID: "account", DisplayName: "Aurora Player", Handle: "auroraone"})
		if len(f.calls) != 1 || f.calls[0] != "auroraone" {
			t.Fatalf("derived name: %v", f.calls)
		}
		if taken {
			if !errors.Is(err, coreclient.ErrOnlineIDTaken) {
				t.Fatal(err)
			}
		} else if err != nil || link.OnlineID != "auroraone" {
			t.Fatal(link, err)
		}
	}
}
