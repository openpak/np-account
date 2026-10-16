package community

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
)

// VSH reads a 65-byte signature comment plus LF before the XML. The MAC covers
// only the XML, zero-padded to a 64-byte boundary (FUN_0022cd90 / 0022c698).
func signedResource(body, key []byte) []byte {
	padded := make([]byte, (len(body)+63)&^63)
	copy(padded, body)
	mac := hmac.New(sha1.New, key)
	mac.Write(padded)
	return append([]byte(fmt.Sprintf("<!--Sce-Np-Signature: %x-->\n", mac.Sum(nil))), body...)
}

func (s *Service) trophyStatus(w http.ResponseWriter, r *http.Request) {
	if len(s.TrophyResourceKey) != 20 {
		http.Error(w, "resource signing unavailable", http.StatusServiceUnavailable)
		return
	}
	// Discovery opens only when the private persistent backend answers.
	xml := `<?xml version="1.0" encoding="UTF-8"?><nptrophy status="maintenance"><interval>60</interval></nptrophy>`
	if s.Trophies != nil {
		if _, err := s.Trophies.games(r.Context(), "00000000-0000-0000-0000-000000000000"); err == nil {
			xml = `<?xml version="1.0" encoding="UTF-8"?><nptrophy status="alive"><trophy-fqdn>trophy.ww.np.community.playstation.net</trophy-fqdn><interval>60</interval></nptrophy>`
		}
	}
	body := signedResource([]byte(xml), s.TrophyResourceKey)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}
