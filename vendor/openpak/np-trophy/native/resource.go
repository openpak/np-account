package native

import (
	"net/http"
	"openpak/np-common/resource"
	"strconv"
)

func (s *Service) trophyStatus(w http.ResponseWriter, r *http.Request) {
	if len(s.TrophyResourceKey) != 20 {
		http.Error(w, "resource signing unavailable", http.StatusServiceUnavailable)
		return
	}
	// Discovery opens only when the private persistent backend answers.
	xml := `<?xml version="1.0" encoding="UTF-8"?><nptrophy status="maintenance"><interval>60</interval></nptrophy>`
	if s.Trophies != nil {
		if _, err := s.Trophies.Games(r.Context(), "00000000-0000-0000-0000-000000000000"); err == nil {
			xml = `<?xml version="1.0" encoding="UTF-8"?><nptrophy status="alive"><trophy-fqdn>trophy.ww.np.community.playstation.net</trophy-fqdn><interval>60</interval></nptrophy>`
		}
	}
	body := resource.Sign([]byte(xml), s.TrophyResourceKey)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}
