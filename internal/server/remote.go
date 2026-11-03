package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"openpak/np-account/internal/nav"
	"openpak/np-account/internal/oauth"
	"time"
)

// RemoteHandler preserves the existing HTTP/TLS entry point while extracted services own their routes.
// XMPP is routed directly to np-community and never passes through np-account.
// tusURL, scoreURL, updateURL and uploaderURL are optional: without one its paths fall through to the local 404.
func RemoteHandler(auth *oauth.Service, issuer *nav.Service, communityURL, trophyURL, tusURL, scoreURL, updateURL, uploaderURL string) (http.Handler, error) {
	community, err := remote("NP_COMMUNITY_URL", communityURL)
	if err != nil {
		return nil, err
	}
	trophy, err := remote("NP_TROPHY_URL", trophyURL)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	for _, path := range []string{"/basic_view/", "/basic_update/", "/friend_list_view/", "/friend_list_update/", "/a/", "/np/resource/title/", "/nsx/"} {
		mux.Handle(path, community)
	}
	for _, path := range []string{"/trophy/", "/np/resource/trophy/"} {
		mux.Handle(path, trophy)
	}
	for _, opt := range []struct {
		name, url string
		paths     []string
	}{
		{"NP_TUS_URL", tusURL, []string{"/user_storage/", "/tss/", "/np/resource/title/{commid}/storage/"}},
		{"NP_SCORE_URL", scoreURL, []string{"/ranking_update/", "/ranking_view/", "/ranking_clan_view/", "/np/resource/title/{commid}/ranking/"}},
		{"NP_UPDATE_URL", updateURL, []string{"/tpl/"}},
		{"NP_UPLOADER_URL", uploaderURL, []string{"/uploader/"}},
	} {
		if opt.url == "" {
			continue
		}
		h, err := remote(opt.name, opt.url)
		if err != nil {
			return nil, err
		}
		for _, path := range opt.paths {
			mux.Handle(path, h)
		}
	}
	mux.Handle("/", Handler(auth, issuer))
	return mux, nil
}
func remote(name, raw string) (http.Handler, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%s must be an http(s) origin", name)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 10 * time.Second
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Warn("NP upstream unavailable", "service", name, "path", r.URL.Path)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}
	return proxy, nil
}
