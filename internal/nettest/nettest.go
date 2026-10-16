// Package nettest serves the PS3 network connection test URLs. Bodies are
// fixed: get_2m is 2 MiB of a repeating byte pattern, the post endpoints read
// and discard the body and answer 200, trial.txt is a short text.
// The exact responses the firmware expects are UNCONFIRMED.
package nettest

import (
	"io"
	"net/http"
	"strconv"
)

// Get2MSize is the size of the get_2m body.
const Get2MSize = 2 << 20

// maxPost bounds how much of a posted body is read; the rest is dropped with
// the connection.
const maxPost = 16 << 20

// TrialText is the body of /networktest/trial.txt.
const TrialText = "OK\n"

var body2m = func() []byte {
	b := make([]byte, Get2MSize)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}()

// Register adds the network-test routes to mux.
func Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /networktest/get_2m", get2m)
	mux.HandleFunc("POST /networktest/post", post)
	mux.HandleFunc("POST /networktest/post_128", post)
	mux.HandleFunc("GET /networktest/trial.txt", trial)
	mux.HandleFunc("GET /update/ps3/list/{region}/ps3-updatelist.txt", updateList)
}

func get2m(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.Itoa(len(body2m)))
	h.Set("Cache-Control", "no-store")
	w.Write(body2m)
}

func post(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxPost))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

func trial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, TrialText)
}
