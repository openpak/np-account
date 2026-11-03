package native

// Remaining Account Information (regcam CAM) actions. Static RE of regcam_plugin 4.93; see
// research/ps3/regcam-account-information.md. None of these is confirmed on a console.

import (
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cstr is a NUL-terminated string element value. The firmware hands the element pointer to its
// string constructor (FUN_0000204c), so the terminator must be inside the element.
func cstr(s string) []byte { return append([]byte(s), 0) }

// AddressReply is the getAddr reply (regcam FUN_000db818, postal-code lookup): elements 0x4f
// street 1, 0x50 street 2, 0x51 city, 0x52 state/province, 0x36 country, 0x54 postal code. All six
// must exist (a missing one is 0x80023087); zero length is accepted, and the values are C strings.
// Field roles come from the consumers (FUN_0006f8c8), not from a console.
func AddressReply(street1, street2, city, state, country, postal string) []byte {
	return Reply(
		Elem(0x4f, cstr(street1)), Elem(0x50, cstr(street2)), Elem(0x51, cstr(city)),
		Elem(0x52, cstr(state)), Elem(0x36, cstr(country)), Elem(0x54, cstr(postal)))
}

// ResAddressReply is the getResAddr reply (FUN_000dbed4): 0x4f, 0x52 and 0x36 only.
func ResAddressReply(street, state, country string) []byte {
	return Reply(Elem(0x4f, cstr(street)), Elem(0x52, cstr(state)), Elem(0x36, cstr(country)))
}

// EmptyListReply is a reply holding one empty tag-1 list: getTranHist (0x6b, FUN_000dac38) and
// getCnslAct (0x74, FUN_000daa74) only need the list element; count 0 makes the UI loop not run.
func EmptyListReply(id uint16) []byte { return Reply(List(id)) }

// ServicesReply is the empty getSrvs reply (FUN_000dd874). Unlike the other lists it is a tag-2
// element: u16 id 0x71, u16 count, u16 first-item index, u16 total (FUN_000de200), all zero here.
func ServicesReply() []byte {
	v := make([]byte, 8)
	binary.BigEndian.PutUint16(v, 0x71)
	return Reply(Elem(2, v))
}

// recentAuth remembers, per client address, the country of the last account that authenticated.
// The firmware sends no cookie and no account identifier after authenticate (regcam never fills
// the session record's cookie string, +0x48), so follow-up reads cannot be tied to an account;
// this read-only guess fills the address country and is wrong behind a shared NAT. Memory only.
type recentAuth struct {
	mu      sync.Mutex
	country map[string]countrySeen
}

type countrySeen struct {
	country string
	at      time.Time
}

const recentAuthTTL = 30 * time.Minute

func clientHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (a *recentAuth) remember(r *http.Request, country string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.country == nil {
		a.country = map[string]countrySeen{}
	}
	now := time.Now()
	if len(a.country) > 1024 {
		for k, v := range a.country {
			if now.Sub(v.at) > recentAuthTTL {
				delete(a.country, k)
			}
		}
	}
	a.country[clientHost(r)] = countrySeen{country, now}
}

func (a *recentAuth) recall(r *http.Request) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v, ok := a.country[clientHost(r)]; ok && time.Since(v.at) <= recentAuthTTL {
		return v.country
	}
	return ""
}

func (h *Handler) address(w http.ResponseWriter, r *http.Request) {
	h.reply(w, AddressReply("", "", "", "", strings.ToUpper(h.recent.recall(r)), ""))
}

func (h *Handler) resAddress(w http.ResponseWriter, r *http.Request) {
	h.reply(w, ResAddressReply("", "", strings.ToUpper(h.recent.recall(r))))
}

// unavailable answers the save actions setName, setLid, setOptIn, setWalOpt, remPay and updPass.
// Nothing can be stored: the core has no such fields, the request names no account (no cookie) and
// there is no password-change call. A success reply would claim a change that did not happen, so
// the answer is HTTP 503, the firmware's "service unavailable" (0x80023016).
func (h *Handler) unavailable(w http.ResponseWriter, r *http.Request) {
	h.logger().Info("native: save action refused, not available", "path", r.URL.Path)
	http.Error(w, "not available", http.StatusServiceUnavailable)
}
