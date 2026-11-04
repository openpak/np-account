// Package capture records full requests to a daily JSON-lines file, for protocol discovery on a real
// console (card #130 P0). It is off unless a directory is configured (nphttp reads NP_CAPTURE_DIR).
//
// One file per day, capture-YYYY-MM-DD.jsonl, mode 0600, kept 90 days. Each line is one request: scheme,
// method, host, URI, headers, request body (first 16 KiB, text or base64), status, response headers and
// size. Secrets are masked before anything is written: credential headers, query/form values whose key
// looks like a token, ticket, password, session or key, and the whole body of authentication paths.
package capture

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxBody   = 16 << 10
	retention = 90 * 24 * time.Hour
	masked    = "[masked]"
)

var (
	secretKey = regexp.MustCompile(`(?i)(token|ticket|passw|passwd|pwd|secret|session|sess|cookie|auth|cred|key|sig|rif|rap)`)
	// Whole request bodies of these paths are never stored (credentials travel in them).
	noBody = []string{"/oauth", "/2.0/oauth", "/nav/auth", "/native/reg", "/native/pwd", "/csla", "/native/upgrade"}
)

// Recorder writes the daily files.
type Recorder struct {
	dir string
	now func() time.Time

	mu   sync.Mutex
	day  string
	file *os.File
}

// New creates dir if needed and returns a Recorder.
func New(dir string) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Recorder{dir: dir, now: time.Now}, nil
}

// FromEnv returns a Recorder when dir is not empty, else nil.
func FromEnv(dir string) (*Recorder, error) {
	if dir == "" {
		return nil, nil
	}
	return New(dir)
}

type entry struct {
	Time       string            `json:"time"`
	Kind       string            `json:"kind"`
	Remote     string            `json:"remote,omitempty"`
	Scheme     string            `json:"scheme,omitempty"`
	Method     string            `json:"method,omitempty"`
	Host       string            `json:"host,omitempty"`
	URI        string            `json:"uri,omitempty"`
	Proto      string            `json:"proto,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodyB64    string            `json:"body_b64,omitempty"`
	BodyLen    int64             `json:"body_len,omitempty"`
	BodyCut    bool              `json:"body_truncated,omitempty"`
	BodySkip   string            `json:"body_skipped,omitempty"`
	Status     int               `json:"status,omitempty"`
	RespHeader map[string]string `json:"resp_headers,omitempty"`
	RespLen    int64             `json:"resp_len,omitempty"`
	MS         int64             `json:"ms,omitempty"`
	SNI        string            `json:"sni,omitempty"`
	TLSVers    []uint16          `json:"tls_versions,omitempty"`
	Ciphers    []uint16          `json:"tls_ciphers,omitempty"`
}

// Hello records one TLS client hello (the SNI the console asked for). Use as tlsfront Front.Hello.
func (r *Recorder) Hello(h *tls.ClientHelloInfo) {
	if r == nil {
		return
	}
	r.write(entry{Kind: "tls", Remote: remoteIP(h.Conn), SNI: h.ServerName, TLSVers: h.SupportedVersions, Ciphers: h.CipherSuites})
}

// Wrap records every request served by next except /healthz.
func (r *Recorder) Wrap(next http.Handler) http.Handler {
	if r == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/healthz" {
			next.ServeHTTP(w, req)
			return
		}
		start := r.now()
		e := entry{Kind: "http", Remote: hostOnly(req.RemoteAddr), Method: req.Method, Host: req.Host, URI: maskURI(req.URL), Proto: req.Proto,
			Headers: maskHeaders(req.Header)}
		if req.TLS != nil {
			e.Scheme = "https"
		} else {
			e.Scheme = "http"
		}
		for _, p := range noBody {
			if strings.HasPrefix(req.URL.Path, p) {
				e.BodySkip = "authentication path"
				break
			}
		}
		if req.Body != nil && e.BodySkip == "" {
			b, _ := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
			e.BodyLen = int64(len(b))
			if len(b) > maxBody {
				b, e.BodyCut = b[:maxBody], true
			}
			// Put back what was read plus the unread rest so the handler sees the full body.
			req.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(strings.NewReader(string(b)), req.Body), req.Body}
			if len(b) > 0 {
				if utf8.Valid(b) {
					e.Body = maskBody(string(b), req.Header.Get("Content-Type"))
				} else {
					e.BodyB64 = base64.StdEncoding.EncodeToString(b)
				}
			}
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, req)
		e.Status, e.RespLen, e.MS = sw.status, sw.n, r.now().Sub(start).Milliseconds()
		e.RespHeader = maskHeaders(w.Header())
		r.write(e)
	})
}

func (r *Recorder) write(e entry) {
	t := r.now().UTC()
	e.Time = t.Format(time.RFC3339Nano)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	day := t.Format("2006-01-02")
	if r.file == nil || day != r.day {
		if r.file != nil {
			r.file.Close()
			r.file = nil
		}
		f, err := os.OpenFile(filepath.Join(r.dir, "capture-"+day+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		r.file, r.day = f, day
		r.prune(t)
	}
	r.file.Write(append(b, '\n'))
}

func (r *Recorder) prune(now time.Time) {
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	for _, d := range ents {
		n := d.Name()
		if !strings.HasPrefix(n, "capture-") || !strings.HasSuffix(n, ".jsonl") {
			continue
		}
		if t, err := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(n, "capture-"), ".jsonl")); err == nil && now.Sub(t) > retention {
			os.Remove(filepath.Join(r.dir, n))
		}
	}
}

func maskHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if secretKey.MatchString(k) {
			out[k] = masked
		} else {
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}

func maskURI(u *url.URL) string {
	s := u.EscapedPath()
	if u.RawQuery != "" {
		s += "?" + maskForm(u.RawQuery)
	}
	return s
}

func maskForm(s string) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		k, _, ok := strings.Cut(p, "=")
		if ok {
			if dk, err := url.QueryUnescape(k); err == nil && secretKey.MatchString(dk) {
				parts[i] = k + "=" + masked
			}
		}
	}
	return strings.Join(parts, "&")
}

func maskBody(b, ctype string) string {
	if strings.Contains(ctype, "x-www-form-urlencoded") {
		return maskForm(b)
	}
	return b
}

func remoteIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	return hostOnly(c.RemoteAddr().String())
}

func hostOnly(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	n           int64
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader && code >= 200 {
		w.status, w.wroteHeader = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("capture: underlying writer is not a Hijacker")
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
